import platform
import sys
import os

def supports_color():
    """
    Determina si la terminal actual soporta colores
    
    Returns:
        bool: True si la terminal soporta colores, False en caso contrario
    """
    # Si estamos redirigiendo la salida, no usar colores
    if not sys.stdout.isatty():
        return False
    
    # Plataforma específica
    plat = platform.system()
    supported_platform = plat != 'Windows' or 'ANSICON' in os.environ
    
    # En Windows 10 con versiones recientes de PowerShell/CMD, los colores son soportados
    if plat == 'Windows':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # Verificar si la consola soporta VT100 (Windows 10 build 10586+)
            return kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7) != 0
        except (AttributeError, ImportError):
            # Si no podemos verificar, asumimos que no hay soporte
            return False
    
    # En macOS y Linux, verificar la variable de entorno TERM
    if plat in ['Darwin', 'Linux']:
        return os.environ.get('TERM') not in ['', 'dumb']
    
    return supported_platform

def setup_colors():
    """
    Configura los colores según el sistema operativo y el soporte de la terminal
    
    Returns:
        dict: Diccionario con los códigos de color
    """
    # Verificar si la terminal soporta colores
    if supports_color():
        colors = {
            "normal": "\033[0m",
            "info": "\033[1;33m",
            "red": "\033[1;31m",
            "green": "\033[1;32m",
            "white_bold": "\033[1;37m",
            "detect": "\033[1;34m",
            "banner": "\033[1;33;40m",
            "end_banner": "\033[0m"
        }
    else:
        # Sin soporte de colores
        colors = {
            "normal": "",
            "info": "",
            "red": "",
            "green": "",
            "white_bold": "",
            "detect": "",
            "banner": "",
            "end_banner": ""
        }
    
    return colors

def banner(colors):
    """
    Muestra el banner de la aplicación
    
    Args:
        colors (dict): Diccionario con los códigos de color
    """
    print(colors["banner"] + "                                                                                           " + colors["end_banner"])
    print(colors["banner"] + "M   M   A    GGG  III  CCC         SSSS PPPP   OOO   OOO  FFFFF       M   M   A   III L    " + colors["end_banner"])
    print(colors["banner"] + "MM MM  A A  G      I  C   C       S     P   P O   O O   O F           MM MM  A A   I  L    " + colors["end_banner"])
    print(colors["banner"] + "M M M AAAAA G GG   I  C            SSS  PPPP  O   O O   O FFFF        M M M AAAAA  I  L    " + colors["end_banner"])
    print(colors["banner"] + "M   M A   A G   G  I  C   C           S P     O   O O   O F           M   M A   A  I  L    " + colors["end_banner"])
    print(colors["banner"] + "M   M A   A  GGG  III  CCC        SSSS  P      OOO   OOO  F           M   M A   A III LLLLL" + colors["end_banner"])
    print(colors["banner"] + "                                                                                           " + colors["end_banner"])
    print(" ")

def print_domain_header(domain, colors):
    """
    Imprime el encabezado para el análisis de un dominio
    
    Args:
        domain (str): El dominio a analizar
        colors (dict): Diccionario con los códigos de color
    """
    print(colors["white_bold"] + " ---------------------------------- Analyzing " + domain + " ----------------------------------------") 