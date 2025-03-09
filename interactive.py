"""
Interactive mode for MagicSpoofMail
"""

import os
import sys
import argparse
from profiles import list_profiles, get_profile, apply_profile
from config import load_config, save_config

def get_input(prompt, default=None):
    """
    Request input from the user with a default value
    
    Args:
        prompt (str): Message to display
        default (str, optional): Default value
        
    Returns:
        str: User input or default value
    """
    if default:
        prompt = f"{prompt} [{default}]: "
    else:
        prompt = f"{prompt}: "
    
    user_input = input(prompt).strip()
    if not user_input and default:
        return default
    return user_input

def yes_no_question(prompt, default="y"):
    """
    Ask a yes/no question to the user
    
    Args:
        prompt (str): Question to display
        default (str, optional): Default answer (y/n)
        
    Returns:
        bool: True if the answer is yes, False if no
    """
    valid = {"yes": True, "y": True, "no": False, "n": False}
    if default.lower() in ["y", "yes"]:
        prompt = f"{prompt} [Y/n]: "
    else:
        prompt = f"{prompt} [y/N]: "
    
    while True:
        choice = input(prompt).lower()
        if choice == "":
            return valid[default.lower()]
        elif choice in valid:
            return valid[choice]
        else:
            print("Please answer 'yes' or 'no' (or 'y' or 'n').")

def select_from_list(options, prompt="Select an option"):
    """
    Allow the user to select an option from a list
    
    Args:
        options (list): List of options
        prompt (str): Message to display
        
    Returns:
        any: Selected option or None if canceled
    """
    print(f"\n{prompt}:")
    for i, option in enumerate(options, 1):
        print(f"  {i}. {option}")
    print("  0. Cancel")
    
    while True:
        try:
            choice = int(input("\nOption: "))
            if choice == 0:
                return None
            elif 1 <= choice <= len(options):
                return options[choice - 1]
            else:
                print(f"Please enter a number between 0 and {len(options)}.")
        except ValueError:
            print("Please enter a valid number.")

def interactive_domain_check():
    """
    Interactive mode to verify a domain
    
    Returns:
        argparse.Namespace: Arguments configured interactively
    """
    args = argparse.Namespace()
    
    # Set default values for all necessary attributes
    args.max_lookups = 10
    args.dkim_selectors = None
    args.check_dkim = False
    args.deep_spf = False
    args.check_dmarc_ext = False
    args.check_alignment = False
    args.check_external_reports = False
    args.recommend_dmarc = False
    args.test = False
    args.email = None
    args.smtp = "127.0.0.1"
    args.subject = None
    args.template = None
    args.attachment = None
    args.sender = None
    args.verbose = 0
    args.quiet = False
    args.json_output = False
    args.output_file = None
    args.dmarc_policy = "reject"
    args.dkim_key_min_size = 1024
    args.spf_details = False
    
    print("\n=== Interactive Domain Verification ===\n")
    
    # Request domain
    args.domain = get_input("Enter the domain to verify")
    if not args.domain:
        print("A domain is required to continue.")
        return None
    
    # Ask for common TLDs
    args.common = yes_no_question("Do you want to verify common TLDs for this domain?", "n")
    
    # Select profile
    print("\nAvailable profiles:")
    print(list_profiles())
    profile_name = get_input("Select a profile (or leave blank to customize)", "basic")
    
    if profile_name:
        profile = get_profile(profile_name)
        if profile:
            args = apply_profile(args, profile_name)
            print(f"Profile '{profile_name}' applied: {profile['description']}")
        else:
            print(f"Profile '{profile_name}' not found, using custom configuration.")
    
    # Custom options if no profile was selected or customization is desired
    if not profile_name or yes_no_question("Do you want to customize more options?", "n"):
        args.check_dkim = yes_no_question("Verify DKIM configuration?", "y")
        args.deep_spf = yes_no_question("Perform deep SPF analysis?", "n")
        args.check_dmarc_ext = yes_no_question("Perform extended DMARC analysis?", "n")
        
        if args.check_dkim:
            dkim_selectors = get_input("DKIM selectors to verify (comma-separated, or empty to use defaults)")
            if dkim_selectors:
                args.dkim_selectors = dkim_selectors
            args.check_alignment = yes_no_question("Verify DKIM alignment?", "n")
        
        if args.deep_spf:
            try:
                max_lookups = int(get_input("Maximum number of DNS lookups for SPF", "10"))
                args.max_lookups = max_lookups
            except ValueError:
                args.max_lookups = 10
                print("Invalid value, using default value (10)")
        
        if args.check_dmarc_ext:
            args.check_external_reports = yes_no_question("Verify external DMARC reports?", "n")
            args.recommend_dmarc = yes_no_question("Generate DMARC recommendations?", "y")
            if args.recommend_dmarc:
                policy = get_input("Recommended DMARC policy (none, quarantine, reject)", "reject")
                if policy in ["none", "quarantine", "reject"]:
                    args.dmarc_policy = policy
        
        # Output options
        args.json_output = yes_no_question("Generate output in JSON format?", "n")
        if args.json_output:
            output_file = get_input("Path to output file (or empty to display on screen)")
            if output_file:
                args.output_file = output_file
        
        # Email test options
        args.test = yes_no_question("Send test email if vulnerability is detected?", "n")
        if args.test:
            args.email = get_input("Email address for the test")
            args.smtp = get_input("SMTP server to use", "127.0.0.1")
            args.subject = get_input("Email subject (or empty to use default)")
            args.sender = get_input("Email sender (or empty to use test@domain)")
            
            template = get_input("Path to an HTML template (or empty to use default)")
            if template and os.path.isfile(template):
                args.template = template
            
            attachment = get_input("Path to a file to attach (or empty for no attachment)")
            if attachment and os.path.isfile(attachment):
                args.attachment = attachment
    
    # Ask if configuration should be saved
    if yes_no_question("Save this configuration for future use?", "n"):
        config_name = get_input("Name for this configuration", "default")
        config = vars(args)
        config["name"] = config_name
        
        # Save to configuration file
        current_config = load_config()
        current_config["saved_configs"] = current_config.get("saved_configs", {})
        current_config["saved_configs"][config_name] = config
        save_config(current_config)
        
        print(f"Configuration saved as '{config_name}'")
    
    return args

def interactive_mode():
    """
    Start the complete interactive mode
    
    Returns:
        argparse.Namespace: Arguments configured interactively or None if canceled
    """
    print("\n=== MagicSpoofMail - Interactive Mode ===\n")
    
    options = [
        "Verify a domain",
        "Verify domains from a file",
        "Use a saved configuration",
        "Create a new configuration",
        "View available profiles"
    ]
    
    choice = select_from_list(options, "What would you like to do?")
    
    if choice == "Verify a domain":
        return interactive_domain_check()
    
    elif choice == "Verify domains from a file":
        args = argparse.Namespace()
        
        # Set default values for all necessary attributes
        args.max_lookups = 10
        args.dkim_selectors = None
        args.check_dkim = False
        args.deep_spf = False
        args.check_dmarc_ext = False
        args.check_alignment = False
        args.check_external_reports = False
        args.recommend_dmarc = False
        args.test = False
        args.email = None
        args.smtp = "127.0.0.1"
        args.subject = None
        args.template = None
        args.attachment = None
        args.sender = None
        args.verbose = 0
        args.quiet = False
        args.json_output = False
        args.output_file = None
        args.dmarc_policy = "reject"
        args.dkim_key_min_size = 1024
        args.spf_details = False
        args.common = False
        args.domain = None
        
        args.file = get_input("Path to file with domain list")
        if not args.file or not os.path.isfile(args.file):
            print("File not found.")
            return None
        
        # Select profile
        profile_name = get_input("Select a profile (or leave blank to customize)", "basic")
        if profile_name:
            args = apply_profile(args, profile_name)
            print(f"Profile '{profile_name}' applied")
        
        # Custom options
        if yes_no_question("Do you want to customize more options?", "n"):
            args.check_dkim = yes_no_question("Verify DKIM configuration?", "y")
            args.deep_spf = yes_no_question("Perform deep SPF analysis?", "n")
            args.check_dmarc_ext = yes_no_question("Perform extended DMARC analysis?", "n")
            
            if args.check_dkim:
                dkim_selectors = get_input("DKIM selectors to verify (comma-separated, or empty to use defaults)")
                if dkim_selectors:
                    args.dkim_selectors = dkim_selectors
                args.check_alignment = yes_no_question("Verify DKIM alignment?", "n")
            
            if args.deep_spf:
                try:
                    max_lookups = int(get_input("Maximum number of DNS lookups for SPF", "10"))
                    args.max_lookups = max_lookups
                except ValueError:
                    args.max_lookups = 10
                    print("Invalid value, using default value (10)")
            
            if args.check_dmarc_ext:
                args.check_external_reports = yes_no_question("Verify external DMARC reports?", "n")
                args.recommend_dmarc = yes_no_question("Generate DMARC recommendations?", "y")
                if args.recommend_dmarc:
                    policy = get_input("Recommended DMARC policy (none, quarantine, reject)", "reject")
                    if policy in ["none", "quarantine", "reject"]:
                        args.dmarc_policy = policy
            
            # Output options
            args.json_output = yes_no_question("Generate output in JSON format?", "n")
            if args.json_output:
                output_file = get_input("Path to output file (or empty to display on screen)")
                if output_file:
                    args.output_file = output_file
        
        return args
    
    elif choice == "Use a saved configuration":
        config = load_config()
        saved_configs = config.get("saved_configs", {})
        
        if not saved_configs:
            print("No saved configurations.")
            return None
        
        config_names = list(saved_configs.keys())
        selected = select_from_list(config_names, "Select a configuration")
        
        if selected:
            args = argparse.Namespace(**saved_configs[selected])
            # Ensure all necessary attributes are defined
            if not hasattr(args, 'max_lookups'):
                args.max_lookups = 10
            if not hasattr(args, 'dkim_selectors'):
                args.dkim_selectors = None
            if not hasattr(args, 'check_dkim'):
                args.check_dkim = False
            if not hasattr(args, 'deep_spf'):
                args.deep_spf = False
            if not hasattr(args, 'check_dmarc_ext'):
                args.check_dmarc_ext = False
            if not hasattr(args, 'check_alignment'):
                args.check_alignment = False
            if not hasattr(args, 'check_external_reports'):
                args.check_external_reports = False
            if not hasattr(args, 'recommend_dmarc'):
                args.recommend_dmarc = False
            if not hasattr(args, 'dmarc_policy'):
                args.dmarc_policy = "reject"
            if not hasattr(args, 'dkim_key_min_size'):
                args.dkim_key_min_size = 1024
            if not hasattr(args, 'spf_details'):
                args.spf_details = False
            return args
        return None
    
    elif choice == "Create a new configuration":
        # Similar to interactive_domain_check but without executing
        args = interactive_domain_check()
        if args:
            print("\nConfiguration created. You can use it with the command:")
            cmd = "./magicspoofmail.py"
            for key, value in vars(args).items():
                if isinstance(value, bool) and value:
                    cmd += f" --{key}"
                elif not isinstance(value, bool) and value is not None:
                    cmd += f" --{key} {value}"
            print(cmd)
        return None
    
    elif choice == "View available profiles":
        print("\n" + list_profiles())
        return None
    
    return None 