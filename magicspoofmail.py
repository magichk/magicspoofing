#!/usr/bin/env python3
"""
MagicSpoofMail - Herramienta para verificar y probar la suplantación de correo electrónico
"""

import sys
import os
import json
from utils import setup_colors, banner, print_domain_header
from dns_checks import check_spf, check_dmarc, check_spf_recursive, check_dkim, check_dkim_alignment
from email_sender import send_email
from cli import parse_arguments
from profiles import apply_profile, get_profile
from config import load_config, save_config, create_default_config, apply_config_to_args
from interactive import interactive_mode

def process_domain(domain, args, colors):
    """
    Procesa un dominio individual: verifica SPF, DMARC y opcionalmente envía un correo de prueba
    
    Args:
        domain (str): El dominio a procesar
        args (argparse.Namespace): Argumentos de línea de comandos
        colors (dict): Diccionario con los colores para la salida
    """
    print_domain_header(domain, colors)
    
    # Verificar SPF (ahora devuelve 1 si existe, 0 si no)
    flag_spf = check_spf(domain, colors)
    
    # Si se requiere un análisis más profundo de SPF, podemos usar check_spf_recursive
    if flag_spf == 1 and args.deep_spf:
        print(colors["info"] + "\nPerforming deep SPF analysis (recursive)..." + colors["normal"])
        spf_recursive = check_spf_recursive(domain, max_depth=args.max_lookups)
        
        if spf_recursive['lookup_count'] > 10:
            print(colors["red"] + f"[!] Deep analysis shows this domain exceeds the SPF lookup limit: {spf_recursive['lookup_count']}/10" + colors["normal"])
        
        if spf_recursive['errors']:
            print(colors["red"] + "[!] Deep analysis found errors in SPF chain:" + colors["normal"])
            for error in spf_recursive['errors']:
                print(colors["red"] + f"   - {error}" + colors["normal"])
    
    # Verificar DMARC
    flag_dmarc = check_dmarc(domain, colors)
    
    # Verificar DKIM si se solicita
    if args.check_dkim:
        # Si se especifican selectores, usarlos; de lo contrario, usar los predeterminados
        selectors = None
        if args.dkim_selectors:
            selectors = args.dkim_selectors.split(',')
        
        # Verificar DKIM
        dkim_info = check_dkim(domain, colors, selectors=selectors)
        
        # Verificar alineación DKIM si se solicita
        if args.check_alignment:
            alignment_info = check_dkim_alignment(domain, colors)
    
    # Verificar si se puede suplantar el dominio
    can_spoof = False
    
    # Criterios para determinar si se puede suplantar:
    # 1. No hay SPF (flag_spf == 0)
    # 2. DMARC está ausente (flag_dmarc == 0) o mal configurado (flag_dmarc == 1)
    # 3. Si se verificó DKIM y no se encontraron selectores
    if flag_spf == 0:
        can_spoof = True
        print(colors["red"] + "[!] You can spoof this domain based on missing SPF configuration!")
    
    if flag_dmarc == 0 or flag_dmarc == 1:
        can_spoof = True
        if flag_dmarc == 0:
            print(colors["red"] + "[!] You can spoof this domain based on missing DMARC configuration!")
        else:
            print(colors["red"] + "[!] You can spoof this domain based on weak DMARC configuration (p=none)!")
    
    if args.check_dkim and 'dkim_info' in locals() and not dkim_info['selectors_found']:
        can_spoof = True
        print(colors["red"] + "[!] You can spoof this domain based on missing DKIM configuration!")
    
    # Enviar correo de prueba si se solicita y se puede suplantar
    if can_spoof and args.test and args.email:
        smtp = args.smtp if args.smtp else "127.0.0.1"
        send_email(
            domain=domain, 
            destination=args.email, 
            smtp=smtp, 
            colors=colors,
            sender=args.sender,
            subject=args.subject,
            template=args.template,
            attachment=args.attachment
        )
    
    # Si no se puede suplantar, mostrar mensaje
    if not can_spoof:
        print(colors["green"] + "[+]" + colors["white_bold"] + " This domain is well protected against email spoofing!")
    
    # Guardar resultados en formato JSON si se solicita
    if args.json_output or args.output_file:
        results = {
            "domain": domain,
            "spf": {
                "exists": flag_spf == 1,
                "secure": flag_spf == 1
            },
            "dmarc": {
                "exists": flag_dmarc > 0,
                "secure": flag_dmarc == 2
            },
            "dkim": {},
            "can_spoof": can_spoof
        }
        
        if args.check_dkim and 'dkim_info' in locals():
            results["dkim"] = {
                "exists": bool(dkim_info['selectors_found']),
                "selectors": dkim_info['selectors_found'],
                "security_level": dkim_info['security_level']
            }
        
        if args.output_file:
            try:
                with open(args.output_file, 'w') as f:
                    json.dump(results, f, indent=4)
                print(colors["green"] + f"[+] Results saved to {args.output_file}")
            except Exception as e:
                print(colors["red"] + f"[!] Error saving results: {e}")
        
        if args.json_output:
            print(json.dumps(results, indent=4))
    
    print(" ")

def process_common_tlds(domain_name, args, colors):
    """
    Procesa un nombre de dominio con diferentes TLDs comunes
    
    Args:
        domain_name (str): El nombre base del dominio
        args (argparse.Namespace): Argumentos de línea de comandos
        colors (dict): Diccionario con los colores para la salida
    """
    tlds = ['es', 'com', 'fr', 'it', 'co.uk', 'cat', 'de', 'be', 'au', 'xyz']
    
    # Determinar si el dominio ya tiene un TLD
    dot_index = domain_name.find(".")
    
    if dot_index != -1:
        # Si ya tiene un TLD, extraer el nombre base
        base_name = domain_name[0:dot_index]
        for tld in tlds:
            domain_with_tld = f"{base_name}.{tld}"
            process_domain(domain_with_tld, args, colors)
    else:
        # Si no tiene TLD, usar el nombre completo como base
        for tld in tlds:
            domain_with_tld = f"{domain_name}.{tld}"
            process_domain(domain_with_tld, args, colors)

def main():
    """Función principal del programa"""
    # Obtener argumentos de línea de comandos
    args = parse_arguments()
    
    # Configurar colores
    colors = setup_colors()
    
    # Mostrar banner
    banner(colors)
    
    # Crear configuración por defecto si se solicita
    if args.create_config:
        config = create_default_config()
        print(colors["green"] + f"[+] Default configuration created at ~/.magicspoofmail.json")
        print(json.dumps(config, indent=4))
        return
    
    # Cargar configuración si se especifica
    if args.config_file:
        config = load_config(args.config_file)
        args = apply_config_to_args(args, config)
    
    # Aplicar perfil si se especifica
    if args.profile:
        args = apply_profile(args, args.profile)
        print(colors["green"] + f"[+] Using profile: {args.profile}")
    
    # Guardar configuración si se solicita
    if args.save_config:
        config = vars(args)
        config["name"] = args.save_config
        
        current_config = load_config()
        current_config["saved_configs"] = current_config.get("saved_configs", {})
        current_config["saved_configs"][args.save_config] = config
        
        if save_config(current_config):
            print(colors["green"] + f"[+] Configuration saved as '{args.save_config}'")
        else:
            print(colors["red"] + f"[!] Error saving configuration")
    
    # Modo interactivo
    if args.interactive:
        interactive_args = interactive_mode()
        if interactive_args:
            args = interactive_args
        else:
            return
    
    # Asegurarse de que todos los atributos necesarios estén definidos
    if not hasattr(args, 'domain'):
        args.domain = None
    if not hasattr(args, 'file'):
        args.file = None
    if not hasattr(args, 'common'):
        args.common = False
    if not hasattr(args, 'test'):
        args.test = False
    if not hasattr(args, 'email'):
        args.email = None
    if not hasattr(args, 'smtp'):
        args.smtp = "127.0.0.1"
    if not hasattr(args, 'subject'):
        args.subject = None
    if not hasattr(args, 'template'):
        args.template = None
    if not hasattr(args, 'attachment'):
        args.attachment = None
    if not hasattr(args, 'sender'):
        args.sender = None
    if not hasattr(args, 'deep_spf'):
        args.deep_spf = False
    if not hasattr(args, 'spf_details'):
        args.spf_details = False
    if not hasattr(args, 'max_lookups'):
        args.max_lookups = 10
    if not hasattr(args, 'check_dkim'):
        args.check_dkim = False
    if not hasattr(args, 'dkim_selectors'):
        args.dkim_selectors = None
    if not hasattr(args, 'check_alignment'):
        args.check_alignment = False
    if not hasattr(args, 'dkim_key_min_size'):
        args.dkim_key_min_size = 1024
    if not hasattr(args, 'check_dmarc_ext'):
        args.check_dmarc_ext = False
    if not hasattr(args, 'check_external_reports'):
        args.check_external_reports = False
    if not hasattr(args, 'recommend_dmarc'):
        args.recommend_dmarc = False
    if not hasattr(args, 'dmarc_policy'):
        args.dmarc_policy = "reject"
    if not hasattr(args, 'verbose'):
        args.verbose = 0
    if not hasattr(args, 'quiet'):
        args.quiet = False
    if not hasattr(args, 'json_output'):
        args.json_output = False
    if not hasattr(args, 'output_file'):
        args.output_file = None
    
    # Procesar un dominio único
    if args.domain:
        if args.common:
            # Procesar con TLDs comunes
            process_common_tlds(args.domain, args, colors)
        else:
            # Procesar un solo dominio
            process_domain(args.domain, args, colors)

    # Procesar una lista de dominios desde un archivo
    if args.file:
        try:
            with open(args.file, "r") as file:
                domains = file.readlines()
                
            for domain in domains:
                domain = domain.strip()
                if domain:  # Ignorar líneas vacías
                    process_domain(domain, args, colors)
        except Exception as e:
            print(colors["red"] + f"[!] Error reading file: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
