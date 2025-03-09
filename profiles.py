"""
Predefined configuration profiles for MagicSpoofMail
"""

# Predefined profiles for different use scenarios
PROFILES = {
    # Basic profile: quick verification of SPF, DKIM and DMARC
    'basic': {
        'description': 'Basic verification of SPF, DKIM and DMARC',
        'options': {
            'check_dkim': True,
            'check_dmarc_ext': False,
            'deep_spf': False,
            'spf_details': False,
            'check_alignment': False,
            'check_external_reports': False,
            'recommend_dmarc': False
        }
    },
    
    # Full profile: detailed analysis of all configurations
    'full': {
        'description': 'Comprehensive and detailed analysis of SPF, DKIM and DMARC',
        'options': {
            'check_dkim': True,
            'check_dmarc_ext': True,
            'deep_spf': True,
            'spf_details': True,
            'check_alignment': True,
            'check_external_reports': True,
            'recommend_dmarc': True
        }
    },
    
    # Security profile: focused on identifying vulnerabilities
    'security': {
        'description': 'Analysis focused on identifying security vulnerabilities',
        'options': {
            'check_dkim': True,
            'check_dmarc_ext': True,
            'deep_spf': True,
            'spf_details': False,
            'check_alignment': True,
            'check_external_reports': False,
            'recommend_dmarc': True,
            'dmarc_policy': 'reject'
        }
    },
    
    # Test profile: for sending test emails
    'test': {
        'description': 'Basic verification and test email sending',
        'options': {
            'test': True,
            'check_dkim': True,
            'check_dmarc_ext': False,
            'deep_spf': False,
            'spf_details': False,
            'check_alignment': False
        }
    },
    
    # Reports profile: focused on report configuration
    'reports': {
        'description': 'Analysis of DMARC report configuration',
        'options': {
            'check_dkim': False,
            'check_dmarc_ext': True,
            'deep_spf': False,
            'spf_details': False,
            'check_alignment': False,
            'check_external_reports': True,
            'recommend_dmarc': True
        }
    }
}

def get_profile(profile_name):
    """
    Gets a configuration profile by its name
    
    Args:
        profile_name (str): Profile name
        
    Returns:
        dict: Profile configuration or None if it doesn't exist
    """
    return PROFILES.get(profile_name.lower())

def list_profiles():
    """
    Lists all available profiles
    
    Returns:
        str: Formatted text with the list of profiles
    """
    result = "Available profiles:\n"
    for name, profile in PROFILES.items():
        result += f"  - {name}: {profile['description']}\n"
    return result

def apply_profile(args, profile_name):
    """
    Applies a configuration profile to the arguments
    
    Args:
        args (argparse.Namespace): Command line arguments
        profile_name (str): Name of the profile to apply
        
    Returns:
        argparse.Namespace: Modified arguments
    """
    profile = get_profile(profile_name)
    if not profile:
        return args
    
    # Apply profile options
    for option, value in profile['options'].items():
        if not hasattr(args, option) or getattr(args, option) is None or isinstance(getattr(args, option), bool):
            setattr(args, option, value)
    
    return args 