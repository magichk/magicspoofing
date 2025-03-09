import pydig
import re
import ipaddress
import socket
import dns.resolver

def check_spf(domain, colors):
    """
    Performs detailed verification of a domain's SPF configuration
    
    Args:
        domain (str): The domain to verify
        colors (dict): Dictionary with colors for output
        
    Returns:
        dict: Dictionary with detailed information about the SPF configuration
    """
    spf_records = pydig.query(domain, 'TXT')
    spf_found = False
    spf_record = None
    spf_info = {
        'exists': False,
        'record': None,
        'version': None,
        'mechanisms': [],
        'modifiers': {},
        'includes': [],
        'redirects': None,
        'ip4': [],
        'ip6': [],
        'a': [],
        'mx': [],
        'ptr': [],
        'all_mechanism': None,
        'security_level': 'None',
        'issues': [],
        'recommendations': [],
        'lookup_count': 0,
        'lookup_limit_exceeded': False
    }
    
    # Search for SPF record
    for record in spf_records:
        if "v=spf1" in record:
            spf_found = True
            spf_record = record
            spf_info['exists'] = True
            spf_info['record'] = record
            break
    
    # If SPF is not found, return result
    if not spf_found:
        print(colors["green"] + "[" + colors["red"] + "-" + colors["green"] + "]" + 
              colors["red"] + " This domain hasn't SPF config yet")
        spf_info['issues'].append("No SPF record found")
        spf_info['recommendations'].append("Implement SPF record to prevent email spoofing")
        return spf_info
    
    print(colors["green"] + "[+]" + colors["white_bold"] + " SPF is present: " + spf_record)
    
    # Analyze SPF version
    if "v=spf1" in spf_record:
        spf_info['version'] = "spf1"
    
    # Clean the SPF record by removing quotes
    clean_record = spf_record.strip('"\'')
    
    # Analyze mechanisms and modifiers
    parts = clean_record.split()
    
    for part in parts:
        # Skip version
        if part.startswith("v="):
            continue
        
        # Analyze "all" mechanism
        if part in ["all", "+all", "-all", "~all", "?all"]:
            spf_info['all_mechanism'] = part
            spf_info['mechanisms'].append(part)
            
            # Evaluate security level based on the "all" mechanism
            if part == "-all":
                spf_info['security_level'] = "High"
            elif part == "~all":
                spf_info['security_level'] = "Medium"
                spf_info['issues'].append("Using ~all (softfail) instead of -all (fail)")
                spf_info['recommendations'].append("Consider using -all for stronger protection")
            elif part == "?all":
                spf_info['security_level'] = "Low"
                spf_info['issues'].append("Using ?all (neutral) provides minimal protection")
                spf_info['recommendations'].append("Consider using -all for stronger protection")
            elif part in ["all", "+all"]:
                spf_info['security_level'] = "None"
                spf_info['issues'].append("Using +all allows any server to send email as your domain")
                spf_info['recommendations'].append("Change to -all to prevent email spoofing")
        
        # Analyze "include" mechanism
        elif part.startswith("include:"):
            included_domain = part[8:]
            spf_info['includes'].append(included_domain)
            spf_info['mechanisms'].append(part)
            spf_info['lookup_count'] += 1  # Each include generates a DNS lookup
        
        # Analyze "redirect" mechanism
        elif part.startswith("redirect="):
            redirect_domain = part[9:]
            spf_info['redirects'] = redirect_domain
            spf_info['modifiers'][part.split('=')[0]] = redirect_domain
            spf_info['lookup_count'] += 1  # redirect generates a DNS lookup
        
        # Analyze "ip4" mechanism
        elif part.startswith("ip4:"):
            ip4 = part[4:]
            spf_info['ip4'].append(ip4)
            spf_info['mechanisms'].append(part)
        
        # Analyze "ip6" mechanism
        elif part.startswith("ip6:"):
            ip6 = part[4:]
            spf_info['ip6'].append(ip6)
            spf_info['mechanisms'].append(part)
        
        # Analyze "a" mechanism
        elif part.startswith("a:") or part == "a":
            if part == "a":
                spf_info['a'].append(domain)
            else:
                a_domain = part[2:]
                spf_info['a'].append(a_domain)
            spf_info['mechanisms'].append(part)
            spf_info['lookup_count'] += 1  # a generates a DNS lookup
        
        # Analyze "mx" mechanism
        elif part.startswith("mx:") or part == "mx":
            if part == "mx":
                spf_info['mx'].append(domain)
            else:
                mx_domain = part[3:]
                spf_info['mx'].append(mx_domain)
            spf_info['mechanisms'].append(part)
            spf_info['lookup_count'] += 1  # mx generates a DNS lookup
        
        # Analyze "ptr" (deprecated and not recommended)
        elif part.startswith("ptr:") or part == "ptr":
            if part == "ptr":
                spf_info['ptr'].append(domain)
            else:
                ptr_domain = part[4:]
                spf_info['ptr'].append(ptr_domain)
            spf_info['mechanisms'].append(part)
            spf_info['lookup_count'] += 1  # ptr generates multiple DNS lookups
            spf_info['issues'].append("Using ptr mechanism which is deprecated and not recommended")
            spf_info['recommendations'].append("Remove ptr mechanism and use ip4/ip6 instead")
        
        # Other modifiers
        elif "=" in part:
            modifier_name, modifier_value = part.split('=', 1)
            spf_info['modifiers'][modifier_name] = modifier_value
    
    # Check for common issues
    
    # 1. Check if the "all" mechanism is missing
    if not spf_info['all_mechanism']:
        spf_info['issues'].append("Missing 'all' mechanism at the end of SPF record")
        spf_info['recommendations'].append("Add '-all' at the end of your SPF record")
    
    # 2. Check if there are too many mechanisms that generate DNS lookups
    if spf_info['lookup_count'] > 10:
        spf_info['lookup_limit_exceeded'] = True
        spf_info['issues'].append(f"SPF record exceeds the 10 DNS lookup limit ({spf_info['lookup_count']} lookups)")
        spf_info['recommendations'].append("Reduce the number of mechanisms that require DNS lookups (include, a, mx, ptr, redirect)")
    elif spf_info['lookup_count'] > 8:
        spf_info['issues'].append(f"SPF record is close to the 10 DNS lookup limit ({spf_info['lookup_count']} lookups)")
        spf_info['recommendations'].append("Consider consolidating DNS lookups to stay well below the limit of 10")
    
    # 3. Check if there are redundant or overlapping mechanisms
    if len(spf_info['ip4']) > 1:
        # Check for IP overlaps
        for i, ip1 in enumerate(spf_info['ip4']):
            for j, ip2 in enumerate(spf_info['ip4']):
                if i != j and is_ip_overlap(ip1, ip2):
                    spf_info['issues'].append(f"Overlapping IP ranges: {ip1} and {ip2}")
                    spf_info['recommendations'].append("Consolidate overlapping IP ranges")
    
    # 4. Check if "ptr" (deprecated) is used
    if spf_info['ptr']:
        spf_info['issues'].append("Using ptr mechanism which is deprecated and not recommended")
        spf_info['recommendations'].append("Remove ptr mechanism and use ip4/ip6 instead")
    
    # 5. Check if both "redirect" and "all" mechanisms are present (conflict)
    if spf_info['redirects'] and spf_info['all_mechanism']:
        spf_info['issues'].append("Both redirect and all mechanisms present, all will be ignored")
        spf_info['recommendations'].append("Remove either redirect or all mechanism")
    
    # 6. Check if the record is too long (more than 255 characters)
    if len(spf_record) > 255:
        spf_info['issues'].append(f"SPF record is too long ({len(spf_record)} characters, max recommended is 255)")
        spf_info['recommendations'].append("Split the record using include: mechanism or reduce the number of mechanisms")
    
    # 7. Check if there are nonexistent domains in includes
    for included_domain in spf_info['includes']:
        try:
            included_spf = pydig.query(included_domain, 'TXT')
            spf_found = False
            for record in included_spf:
                if "v=spf1" in record:
                    spf_found = True
                    break
            
            if not spf_found:
                spf_info['issues'].append(f"Included domain {included_domain} does not have a valid SPF record")
                spf_info['recommendations'].append(f"Remove or fix the include:{included_domain} mechanism")
        except Exception:
            spf_info['issues'].append(f"Error checking included domain {included_domain}")
    
    # 8. Check if there are exp= (explanation) mechanisms
    if 'exp' in spf_info['modifiers']:
        print(colors["green"] + "[+]" + colors["white_bold"] + " SPF has explanation modifier: " + spf_info['modifiers']['exp'])
    else:
        spf_info['recommendations'].append("Consider adding an exp= modifier to provide a custom error message")
    
    # Print detailed information
    if spf_info['exists']:
        print(colors["green"] + "[+]" + colors["white_bold"] + " SPF Version: " + spf_info['version'])
        
        if spf_info['mechanisms']:
            print(colors["green"] + "[+]" + colors["white_bold"] + " SPF Mechanisms: " + ", ".join(spf_info['mechanisms']))
        
        if spf_info['includes']:
            print(colors["green"] + "[+]" + colors["white_bold"] + " SPF Includes: " + ", ".join(spf_info['includes']))
        
        if spf_info['ip4']:
            print(colors["green"] + "[+]" + colors["white_bold"] + " SPF IP4 Addresses: " + ", ".join(spf_info['ip4']))
        
        if spf_info['ip6']:
            print(colors["green"] + "[+]" + colors["white_bold"] + " SPF IP6 Addresses: " + ", ".join(spf_info['ip6']))
        
        if spf_info['all_mechanism']:
            print(colors["green"] + "[+]" + colors["white_bold"] + " SPF All Mechanism: " + spf_info['all_mechanism'])
            
            # Show security level with appropriate color
            security_color = colors["red"]
            if spf_info['security_level'] == "High":
                security_color = colors["green"]
            elif spf_info['security_level'] == "Medium":
                security_color = colors["info"]
            
            print(colors["green"] + "[+]" + colors["white_bold"] + " SPF Security Level: " + 
                  security_color + spf_info['security_level'])
        
        # Show DNS lookup count
        lookup_color = colors["green"]
        if spf_info['lookup_limit_exceeded']:
            lookup_color = colors["red"]
        elif spf_info['lookup_count'] > 8:
            lookup_color = colors["info"]
        
        print(colors["green"] + "[+]" + colors["white_bold"] + " SPF DNS Lookups: " + 
              lookup_color + str(spf_info['lookup_count']) + "/10")
        
        # Show found issues
        if spf_info['issues']:
            print(colors["green"] + "[" + colors["red"] + "!" + colors["green"] + "]" + 
                  colors["red"] + " SPF Issues Found:")
            for issue in spf_info['issues']:
                print(colors["red"] + "   - " + issue)
        
        # Show recommendations
        if spf_info['recommendations']:
            print(colors["green"] + "[" + colors["info"] + "i" + colors["green"] + "]" + 
                  colors["info"] + " SPF Recommendations:")
            for recommendation in spf_info['recommendations']:
                print(colors["info"] + "   - " + recommendation)
    
    # Return 1 if SPF exists, 0 if not (to maintain compatibility with existing code)
    return 1 if spf_found else 0

def is_ip_overlap(ip1, ip2):
    """
    Checks if there is an overlap between two IP ranges
    
    Args:
        ip1 (str): First IP range (CIDR format)
        ip2 (str): Second IP range (CIDR format)
        
    Returns:
        bool: True if there is an overlap, False if not
    """
    try:
        # Convert to IPv4 network objects
        network1 = ipaddress.ip_network(ip1, strict=False)
        network2 = ipaddress.ip_network(ip2, strict=False)
        
        # Check for overlap
        return network1.overlaps(network2)
    except ValueError:
        # If there's an error parsing IPs, return False
        return False

def check_spf_recursive(domain, max_depth=10, current_depth=0, visited=None):
    """
    Verifica recursivamente los registros SPF para detectar problemas de búsqueda DNS
    
    Args:
        domain (str): El dominio a verificar
        max_depth (int): Profundidad máxima de recursión
        current_depth (int): Profundidad actual de recursión
        visited (set): Conjunto de dominios ya visitados
        
    Returns:
        dict: Información sobre las búsquedas DNS
    """
    if visited is None:
        visited = set()
    
    if current_depth > max_depth:
        return {
            'lookup_count': 0,
            'error': f"Max recursion depth exceeded ({max_depth})"
        }
    
    if domain in visited:
        return {
            'lookup_count': 0,
            'error': f"Circular reference detected for domain {domain}"
        }
    
    visited.add(domain)
    
    result = {
        'lookup_count': 1,  # La consulta inicial cuenta como una búsqueda
        'includes': [],
        'errors': []
    }
    
    try:
        spf_records = pydig.query(domain, 'TXT')
        spf_record = None
        
        for record in spf_records:
            if "v=spf1" in record:
                spf_record = record
                break
        
        if not spf_record:
            result['errors'].append(f"No SPF record found for {domain}")
            return result
        
        parts = spf_record.split()
        
        for part in parts:
            if part.startswith("include:"):
                included_domain = part[8:]
                result['includes'].append(included_domain)
                
                # Verificar recursivamente el dominio incluido
                included_result = check_spf_recursive(
                    included_domain, 
                    max_depth, 
                    current_depth + 1,
                    visited.copy()
                )
                
                result['lookup_count'] += included_result.get('lookup_count', 0)
                
                if 'error' in included_result:
                    result['errors'].append(included_result['error'])
                
                if 'errors' in included_result:
                    result['errors'].extend(included_result['errors'])
            
            elif part.startswith("redirect="):
                redirect_domain = part[9:]
                
                # Verificar recursivamente el dominio de redirección
                redirect_result = check_spf_recursive(
                    redirect_domain, 
                    max_depth, 
                    current_depth + 1,
                    visited.copy()
                )
                
                result['lookup_count'] += redirect_result.get('lookup_count', 0)
                
                if 'error' in redirect_result:
                    result['errors'].append(redirect_result['error'])
                
                if 'errors' in redirect_result:
                    result['errors'].extend(redirect_result['errors'])
            
            elif part.startswith("a:") or part == "a":
                result['lookup_count'] += 1
            
            elif part.startswith("mx:") or part == "mx":
                result['lookup_count'] += 1
            
            elif part.startswith("ptr:") or part == "ptr":
                result['lookup_count'] += 1
    
    except Exception as e:
        result['errors'].append(f"Error checking SPF for {domain}: {str(e)}")
    
    return result

def check_dmarc(domain, colors):
    """
    Verifica la configuración DMARC de un dominio de manera detallada
    
    Args:
        domain (str): El dominio a verificar
        colors (dict): Diccionario con los colores para la salida
        
    Returns:
        int: 0 si no hay DMARC, 1 si está mal configurado, 2 si está bien configurado
    """
    dmarc_records = pydig.query('_dmarc.' + domain, 'TXT')
    dmarc_found = False
    dmarc_record = None
    dmarc_info = {
        'exists': False,
        'record': None,
        'version': None,
        'policy': None,
        'subdomain_policy': None,
        'pct': None,
        'rua': [],
        'ruf': [],
        'adkim': None,
        'aspf': None,
        'fo': None,
        'rf': None,
        'ri': None,
        'security_level': 'None',
        'issues': [],
        'recommendations': []
    }
    
    # Buscar registro DMARC
    for record in dmarc_records:
        if "v=DMARC1" in record:
            dmarc_found = True
            dmarc_record = record
            dmarc_info['exists'] = True
            dmarc_info['record'] = record
            break
    
    # Si no se encuentra DMARC, devolver resultado
    if not dmarc_found:
        print(colors["green"] + "[" + colors["red"] + "-" + colors["green"] + "]" + 
              colors["red"] + " This domain hasn't DMARC register")
        dmarc_info['issues'].append("No DMARC record found")
        dmarc_info['recommendations'].append("Implement DMARC record to prevent email spoofing")
        return 0
    
    print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC is present: " + dmarc_record)
    
    # Analizar el registro DMARC en detalle
    analyze_dmarc_record(domain, dmarc_record, dmarc_info, colors)
    
    # Mostrar nivel de seguridad
    security_color = colors["red"]
    if dmarc_info['security_level'] == "High":
        security_color = colors["green"]
    elif dmarc_info['security_level'] == "Medium":
        security_color = colors["info"]
    elif dmarc_info['security_level'] == "Low":
        security_color = colors["red"]
    
    print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC Security Level: " + 
          security_color + dmarc_info['security_level'])
    
    # Mostrar problemas encontrados
    if dmarc_info['issues']:
        print(colors["green"] + "[" + colors["red"] + "!" + colors["green"] + "]" + 
              colors["red"] + " DMARC Issues Found:")
        for issue in dmarc_info['issues']:
            print(colors["red"] + "   - " + issue)
    
    # Mostrar recomendaciones
    if dmarc_info['recommendations']:
        print(colors["green"] + "[" + colors["info"] + "i" + colors["green"] + "]" + 
              colors["info"] + " DMARC Recommendations:")
        for recommendation in dmarc_info['recommendations']:
            print(colors["info"] + "   - " + recommendation)
    
    # Devolver 0 si no hay DMARC, 1 si está mal configurado, 2 si está bien configurado
    if not dmarc_found:
        return 0
    elif dmarc_info['policy'] == 'none' or dmarc_info['security_level'] in ['None', 'Low']:
        return 1
    else:
        return 2

def check_dkim(domain, colors, selectors=None):
    """
    Verifica la configuración DKIM de un dominio
    
    Args:
        domain (str): El dominio a verificar
        colors (dict): Diccionario con los colores para la salida
        selectors (list, optional): Lista de selectores DKIM a verificar. Si es None, se utilizarán selectores comunes.
        
    Returns:
        dict: Diccionario con información detallada sobre la configuración DKIM
    """
    if selectors is None:
        # Lista de selectores DKIM comunes
        selectors = [
            "default", "dkim", "k1", "key1", "selector1", "selector2", "s1", "s2", 
            "mail", "email", "google", "mta", "mx", "m1", "m2", "dk", "dkim1", "dkim2",
            "smtp", "amazonses", "zoho", "protonmail", "mandrill", "sendgrid"
        ]
    
    dkim_info = {
        'domain': domain,
        'selectors_found': [],
        'records': {},
        'issues': [],
        'recommendations': [],
        'security_level': 'None'
    }
    
    print(colors["white_bold"] + "\nChecking DKIM configuration for " + domain)
    print(colors["info"] + "Testing " + str(len(selectors)) + " common DKIM selectors..." + colors["normal"])
    
    # Verificar cada selector
    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            # Intentar resolver el registro TXT para el selector DKIM
            dkim_records = pydig.query(dkim_domain, 'TXT')
            
            if dkim_records:
                dkim_info['selectors_found'].append(selector)
                dkim_info['records'][selector] = dkim_records[0]
                
                print(colors["green"] + "[+]" + colors["white_bold"] + f" DKIM selector found: {selector}")
                print(colors["green"] + "   " + colors["white_bold"] + f"Record: {dkim_records[0]}")
                
                # Analizar el registro DKIM
                analyze_dkim_record(selector, dkim_records[0], dkim_info, colors)
        except Exception as e:
            # Ignorar errores de resolución (significa que el selector no existe)
            pass
    
    # Verificar si se encontraron selectores
    if not dkim_info['selectors_found']:
        print(colors["green"] + "[" + colors["red"] + "-" + colors["green"] + "]" + 
              colors["red"] + " No DKIM selectors found for this domain")
        dkim_info['issues'].append("No DKIM selectors found")
        dkim_info['recommendations'].append("Implement DKIM to improve email authentication")
        return dkim_info
    
    # Evaluar nivel de seguridad general
    if dkim_info['security_level'] == 'None':
        dkim_info['security_level'] = 'High'
        for selector in dkim_info['selectors_found']:
            if dkim_info.get(f'{selector}_security_level', 'None') != 'High':
                dkim_info['security_level'] = 'Medium'
                break
    
    # Mostrar nivel de seguridad
    security_color = colors["red"]
    if dkim_info['security_level'] == "High":
        security_color = colors["green"]
    elif dkim_info['security_level'] == "Medium":
        security_color = colors["info"]
    
    print(colors["green"] + "[+]" + colors["white_bold"] + " DKIM Security Level: " + 
          security_color + dkim_info['security_level'])
    
    # Mostrar problemas encontrados
    if dkim_info['issues']:
        print(colors["green"] + "[" + colors["red"] + "!" + colors["green"] + "]" + 
              colors["red"] + " DKIM Issues Found:")
        for issue in dkim_info['issues']:
            print(colors["red"] + "   - " + issue)
    
    # Mostrar recomendaciones
    if dkim_info['recommendations']:
        print(colors["green"] + "[" + colors["info"] + "i" + colors["green"] + "]" + 
              colors["info"] + " DKIM Recommendations:")
        for recommendation in dkim_info['recommendations']:
            print(colors["info"] + "   - " + recommendation)
    
    return dkim_info

def analyze_dkim_record(selector, record, dkim_info, colors):
    """
    Analiza un registro DKIM para detectar problemas y evaluar su seguridad
    
    Args:
        selector (str): El selector DKIM
        record (str): El registro DKIM
        dkim_info (dict): Diccionario con información sobre DKIM
        colors (dict): Diccionario con los colores para la salida
    """
    # Inicializar información del selector
    dkim_info[f'{selector}_version'] = None
    dkim_info[f'{selector}_key_type'] = None
    dkim_info[f'{selector}_key_size'] = None
    dkim_info[f'{selector}_testing_mode'] = False
    dkim_info[f'{selector}_security_level'] = 'None'
    
    # Extraer campos del registro DKIM
    fields = {}
    for field in record.split(';'):
        field = field.strip()
        if '=' in field:
            key, value = field.split('=', 1)
            fields[key.strip()] = value.strip()
    
    # Verificar versión
    if 'v' in fields:
        dkim_info[f'{selector}_version'] = fields['v']
        print(colors["green"] + "   " + colors["white_bold"] + f"Version: {fields['v']}")
        
        if fields['v'] != 'DKIM1':
            dkim_info['issues'].append(f"Selector {selector} uses non-standard DKIM version: {fields['v']}")
            dkim_info['recommendations'].append(f"Use standard DKIM version (DKIM1) for selector {selector}")
    else:
        dkim_info['issues'].append(f"Selector {selector} missing version field")
        dkim_info['recommendations'].append(f"Add version field (v=DKIM1) to selector {selector}")
    
    # Verificar tipo de clave
    if 'k' in fields:
        dkim_info[f'{selector}_key_type'] = fields['k']
        print(colors["green"] + "   " + colors["white_bold"] + f"Key type: {fields['k']}")
        
        if fields['k'] not in ['rsa', 'ed25519']:
            dkim_info['issues'].append(f"Selector {selector} uses non-standard key type: {fields['k']}")
            dkim_info['recommendations'].append(f"Use standard key types (rsa or ed25519) for selector {selector}")
    else:
        # Por defecto es RSA si no se especifica
        dkim_info[f'{selector}_key_type'] = 'rsa'
        print(colors["green"] + "   " + colors["white_bold"] + "Key type: rsa (default)")
    
    # Verificar clave pública
    if 'p' in fields:
        if fields['p'] == '':
            dkim_info['issues'].append(f"Selector {selector} has revoked key (p=)")
            dkim_info['recommendations'].append(f"Generate new DKIM key for selector {selector}")
            print(colors["red"] + "   " + colors["white_bold"] + "Key: REVOKED")
        else:
            # Estimar tamaño de la clave basado en la longitud de la clave pública
            key_length = len(fields['p'])
            estimated_key_size = estimate_key_size(key_length)
            dkim_info[f'{selector}_key_size'] = estimated_key_size
            
            key_size_color = colors["green"]
            if estimated_key_size < 1024:
                key_size_color = colors["red"]
                dkim_info['issues'].append(f"Selector {selector} uses weak key size (estimated {estimated_key_size} bits)")
                dkim_info['recommendations'].append(f"Use at least 2048-bit RSA keys for selector {selector}")
                dkim_info[f'{selector}_security_level'] = 'Low'
            elif estimated_key_size < 2048:
                key_size_color = colors["info"]
                dkim_info['issues'].append(f"Selector {selector} uses moderate key size (estimated {estimated_key_size} bits)")
                dkim_info['recommendations'].append(f"Consider upgrading to 2048-bit or 4096-bit RSA keys for selector {selector}")
                dkim_info[f'{selector}_security_level'] = 'Medium'
            else:
                dkim_info[f'{selector}_security_level'] = 'High'
            
            print(colors["green"] + "   " + colors["white_bold"] + "Key size: " + 
                  key_size_color + f"~{estimated_key_size} bits")
    else:
        dkim_info['issues'].append(f"Selector {selector} missing public key field")
        dkim_info['recommendations'].append(f"Add public key field (p=) to selector {selector}")
    
    # Verificar modo de prueba
    if 't' in fields and 'y' in fields.get('t', ''):
        dkim_info[f'{selector}_testing_mode'] = True
        print(colors["info"] + "   " + colors["white_bold"] + "Testing mode: Enabled")
        dkim_info['issues'].append(f"Selector {selector} is in testing mode")
        dkim_info['recommendations'].append(f"Disable testing mode for selector {selector} when ready for production")
        dkim_info[f'{selector}_security_level'] = 'Low'
    
    # Verificar servicio
    if 's' in fields:
        services = fields['s'].split(':')
        print(colors["green"] + "   " + colors["white_bold"] + f"Services: {', '.join(services)}")
        
        if '*' in services:
            print(colors["info"] + "   " + colors["white_bold"] + "All services allowed")
        elif 'email' not in services:
            dkim_info['issues'].append(f"Selector {selector} may not be configured for email")
            dkim_info['recommendations'].append(f"Add email service to selector {selector}")
    
    # Verificar flags
    if 'h' in fields:
        hash_algorithms = fields['h'].split(':')
        print(colors["green"] + "   " + colors["white_bold"] + f"Hash algorithms: {', '.join(hash_algorithms)}")
        
        if 'sha1' in hash_algorithms and 'sha256' not in hash_algorithms:
            dkim_info['issues'].append(f"Selector {selector} uses weak hash algorithm (SHA-1)")
            dkim_info['recommendations'].append(f"Use SHA-256 hash algorithm for selector {selector}")
            if dkim_info[f'{selector}_security_level'] == 'High':
                dkim_info[f'{selector}_security_level'] = 'Medium'

def estimate_key_size(key_length):
    """
    Estima el tamaño de la clave RSA basado en la longitud de la clave pública codificada en base64
    
    Args:
        key_length (int): Longitud de la clave pública codificada en base64
        
    Returns:
        int: Tamaño estimado de la clave en bits
    """
    # Estimación aproximada basada en la longitud de la clave codificada en base64
    if key_length < 100:
        return 512
    elif key_length < 200:
        return 1024
    elif key_length < 400:
        return 2048
    else:
        return 4096

def check_dkim_alignment(domain, colors):
    """
    Verifica la alineación DKIM con el dominio
    
    Args:
        domain (str): El dominio a verificar
        colors (dict): Diccionario con los colores para la salida
        
    Returns:
        dict: Diccionario con información sobre la alineación DKIM
    """
    alignment_info = {
        'domain': domain,
        'mx_records': [],
        'alignment_issues': [],
        'recommendations': []
    }
    
    print(colors["white_bold"] + "\nChecking DKIM alignment for " + domain)
    
    # Obtener registros MX
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        
        for mx in mx_records:
            mx_domain = str(mx.exchange).rstrip('.')
            alignment_info['mx_records'].append(mx_domain)
            
            # Verificar si el dominio MX es diferente al dominio principal
            if not mx_domain.endswith(domain):
                print(colors["info"] + f"[i] Mail server {mx_domain} is not aligned with {domain}")
                alignment_info['alignment_issues'].append(f"Mail server {mx_domain} is not aligned with {domain}")
                
                # Verificar si el servidor de correo tiene DKIM configurado
                dkim_info = check_dkim(mx_domain.split('.', 1)[-1], colors, selectors=["default"])
                
                if not dkim_info['selectors_found']:
                    alignment_info['recommendations'].append(f"Configure DKIM for mail server {mx_domain}")
    
    except Exception as e:
        print(colors["red"] + f"[!] Error checking MX records: {str(e)}")
    
    return alignment_info

def analyze_dmarc_record(domain, record, dmarc_info, colors):
    """
    Analiza un registro DMARC en detalle
    
    Args:
        domain (str): El dominio analizado
        record (str): El registro DMARC
        dmarc_info (dict): Diccionario con información sobre DMARC
        colors (dict): Diccionario con los colores para la salida
    """
    # Analizar campos del registro DMARC
    fields = {}
    for field in record.split(';'):
        field = field.strip()
        if '=' in field:
            key, value = field.split('=', 1)
            key = key.strip()
            value = value.strip()
            fields[key] = value
    
    # Analizar versión DMARC
    if 'v' in fields:
        dmarc_info['version'] = fields['v']
        print(colors["green"] + "[+]" + colors["white_bold"] + f" DMARC Version: {fields['v']}")
        
        if fields['v'] != 'DMARC1':
            dmarc_info['issues'].append(f"Non-standard DMARC version: {fields['v']}")
            dmarc_info['recommendations'].append("Use standard DMARC version (DMARC1)")
    
    # Analizar política (p)
    if 'p' in fields:
        dmarc_info['policy'] = fields['p']
        policy_color = colors["red"]
        
        if fields['p'] == 'reject':
            dmarc_info['security_level'] = 'High'
            policy_color = colors["green"]
        elif fields['p'] == 'quarantine':
            dmarc_info['security_level'] = 'Medium'
            policy_color = colors["info"]
            dmarc_info['issues'].append("Using 'quarantine' policy instead of 'reject'")
            dmarc_info['recommendations'].append("Consider using 'reject' policy for stronger protection")
        elif fields['p'] == 'none':
            dmarc_info['security_level'] = 'Low'
            policy_color = colors["red"]
            dmarc_info['issues'].append("Using 'none' policy provides minimal protection")
            dmarc_info['recommendations'].append("Consider using 'quarantine' or 'reject' policy for stronger protection")
        
        print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC Policy: " + policy_color + fields['p'])
    else:
        dmarc_info['issues'].append("Missing required policy field (p)")
        dmarc_info['recommendations'].append("Add policy field (p) to DMARC record")
    
    # Analizar política de subdominio (sp)
    if 'sp' in fields:
        dmarc_info['subdomain_policy'] = fields['sp']
        sp_color = colors["red"]
        
        if fields['sp'] == 'reject':
            sp_color = colors["green"]
        elif fields['sp'] == 'quarantine':
            sp_color = colors["info"]
            if dmarc_info['security_level'] == 'High':
                dmarc_info['security_level'] = 'Medium'
                dmarc_info['issues'].append("Subdomain policy is less strict than domain policy")
                dmarc_info['recommendations'].append("Consider using the same strict policy for subdomains")
        elif fields['sp'] == 'none':
            sp_color = colors["red"]
            if dmarc_info['security_level'] in ['High', 'Medium']:
                dmarc_info['security_level'] = 'Medium'
                dmarc_info['issues'].append("Subdomain policy is much less strict than domain policy")
                dmarc_info['recommendations'].append("Consider using the same strict policy for subdomains")
        
        print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC Subdomain Policy: " + sp_color + fields['sp'])
    else:
        # Si no se especifica, se hereda de la política principal
        dmarc_info['subdomain_policy'] = dmarc_info['policy']
        print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC Subdomain Policy: " + 
              colors["info"] + "Same as main policy (inherited)")
    
    # Analyze percentage (pct)
    if 'pct' in fields:
        # Clean the value to remove any quotes or extra characters
        pct_value = fields['pct'].strip('"\'')
        dmarc_info['pct'] = int(pct_value)
        pct_color = colors["green"]
        
        if dmarc_info['pct'] < 100:
            pct_color = colors["info"]
            if dmarc_info['pct'] < 50:
                pct_color = colors["red"]
                dmarc_info['issues'].append(f"Low percentage value ({dmarc_info['pct']}%) means most messages bypass DMARC")
                dmarc_info['recommendations'].append("Increase percentage to 100% for full protection")
            else:
                dmarc_info['issues'].append(f"Partial percentage value ({dmarc_info['pct']}%) means some messages bypass DMARC")
                dmarc_info['recommendations'].append("Consider increasing percentage to 100% for full protection")
        
        print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC Percentage: " + pct_color + str(dmarc_info['pct']) + "%")
    else:
        # Por defecto es 100%
        dmarc_info['pct'] = 100
        print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC Percentage: " + colors["green"] + "100% (default)")
    
    # Analizar direcciones de informes agregados (rua)
    if 'rua' in fields:
        rua_addresses = fields['rua'].split(',')
        dmarc_info['rua'] = rua_addresses
        
        print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC Aggregate Reports: " + 
              colors["info"] + ", ".join(rua_addresses))
        
        # Verificar si hay direcciones de informes externas
        for address in rua_addresses:
            if 'mailto:' in address:
                email = address.split('mailto:')[1]
                email_domain = email.split('@')[1]
                
                if email_domain != domain and not email_domain.endswith('.' + domain):
                    print(colors["info"] + "   " + colors["white_bold"] + f"External report address: {email}")
                    
                    # Verificar si hay un registro de autorización para informes externos
                    try:
                        external_domain = email_domain
                        authorization_record = pydig.query(f"{domain}._report._dmarc.{external_domain}", 'TXT')
                        
                        if not authorization_record:
                            dmarc_info['issues'].append(f"Missing authorization record for external reports to {external_domain}")
                            dmarc_info['recommendations'].append(f"Add TXT record {domain}._report._dmarc.{external_domain} with value 'v=DMARC1'")
                    except Exception:
                        pass
    else:
        dmarc_info['issues'].append("No aggregate report addresses specified (rua)")
        dmarc_info['recommendations'].append("Add aggregate report addresses (rua) to receive DMARC reports")
    
    # Analizar direcciones de informes forenses (ruf)
    if 'ruf' in fields:
        ruf_addresses = fields['ruf'].split(',')
        dmarc_info['ruf'] = ruf_addresses
        
        print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC Forensic Reports: " + 
              colors["info"] + ", ".join(ruf_addresses))
    
    # Analizar alineación DKIM (adkim)
    if 'adkim' in fields:
        dmarc_info['adkim'] = fields['adkim']
        adkim_color = colors["green"]
        
        if fields['adkim'] == 'r':
            adkim_color = colors["info"]
            print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC DKIM Alignment: " + 
                  adkim_color + "relaxed (default)")
        elif fields['adkim'] == 's':
            adkim_color = colors["green"]
            print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC DKIM Alignment: " + 
                  adkim_color + "strict")
    else:
        # Por defecto es relaxed
        dmarc_info['adkim'] = 'r'
        print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC DKIM Alignment: " + 
              colors["info"] + "relaxed (default)")
    
    # Analizar alineación SPF (aspf)
    if 'aspf' in fields:
        dmarc_info['aspf'] = fields['aspf']
        aspf_color = colors["green"]
        
        if fields['aspf'] == 'r':
            aspf_color = colors["info"]
            print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC SPF Alignment: " + 
                  aspf_color + "relaxed (default)")
        elif fields['aspf'] == 's':
            aspf_color = colors["green"]
            print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC SPF Alignment: " + 
                  aspf_color + "strict")
    else:
        # Por defecto es relaxed
        dmarc_info['aspf'] = 'r'
        print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC SPF Alignment: " + 
              colors["info"] + "relaxed (default)")
    
    # Analizar opciones de informes de fallos (fo)
    if 'fo' in fields:
        dmarc_info['fo'] = fields['fo']
        fo_values = fields['fo'].split(':')
        fo_descriptions = []
        
        for value in fo_values:
            if value == '0':
                fo_descriptions.append("Generate reports if all mechanisms fail (default)")
            elif value == '1':
                fo_descriptions.append("Generate reports if any mechanism fails")
            elif value == 'd':
                fo_descriptions.append("Generate reports if DKIM fails")
            elif value == 's':
                fo_descriptions.append("Generate reports if SPF fails")
        
        print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC Failure Reporting Options: " + 
              colors["info"] + ", ".join(fo_descriptions))
    else:
        # Por defecto es 0
        dmarc_info['fo'] = '0'
        print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC Failure Reporting Options: " + 
              colors["info"] + "Generate reports if all mechanisms fail (default)")
    
    # Analizar formato de informes (rf)
    if 'rf' in fields:
        dmarc_info['rf'] = fields['rf']
        print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC Report Format: " + 
              colors["info"] + fields['rf'])
    
    # Analizar intervalo de informes (ri)
    if 'ri' in fields:
        dmarc_info['ri'] = int(fields['ri'])
        print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC Report Interval: " + 
              colors["info"] + f"{fields['ri']} seconds")
    else:
        # Por defecto es 86400 (24 horas)
        dmarc_info['ri'] = 86400
        print(colors["green"] + "[+]" + colors["white_bold"] + " DMARC Report Interval: " + 
              colors["info"] + "86400 seconds (24 hours, default)")
    
    # Verificar problemas comunes
    
    # 1. Verificar si la política es demasiado permisiva
    if dmarc_info['policy'] == 'none':
        dmarc_info['issues'].append("Policy is set to 'none', which only monitors and doesn't protect")
        dmarc_info['recommendations'].append("Consider implementing 'quarantine' or 'reject' policy")
    
    # 2. Verificar si el porcentaje es bajo
    if dmarc_info['pct'] < 100:
        dmarc_info['issues'].append(f"Percentage is set to {dmarc_info['pct']}%, which means not all messages are evaluated")
        dmarc_info['recommendations'].append("Consider increasing percentage to 100% for full protection")
    
    # 3. Verificar si faltan direcciones de informes
    if not dmarc_info.get('rua', []):
        dmarc_info['issues'].append("No aggregate report addresses specified")
        dmarc_info['recommendations'].append("Add aggregate report addresses (rua) to receive DMARC reports")
    
    # 4. Verificar si hay problemas de sintaxis
    if record.count('v=DMARC1') > 1:
        dmarc_info['issues'].append("Multiple DMARC version tags found")
        dmarc_info['recommendations'].append("Fix DMARC record syntax to have only one version tag") 