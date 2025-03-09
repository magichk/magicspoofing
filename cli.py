import argparse
import sys
import os
from profiles import list_profiles, get_profile

def parse_arguments():
    """
    Parse command line arguments
    
    Returns:
        argparse.Namespace: Object with parsed arguments
    """
    parser = argparse.ArgumentParser(description='Magic Spoof Mail - Tool to verify and test email spoofing')
    
    # Operation modes group
    mode_group = parser.add_argument_group('Operation Modes')
    mode_group.add_argument('-i', "--interactive", action="store_true", dest='interactive',
                        help="Start in interactive mode")
    mode_group.add_argument('-p', "--profile", action="store", dest='profile',
                        help="Use a predefined profile (basic, full, security, test, reports)")
    mode_group.add_argument("--list-profiles", action="store_true", dest='list_profiles',
                        help="List available profiles")
    mode_group.add_argument("--config", action="store", dest='config_file',
                        help="Use a specific configuration file")
    mode_group.add_argument("--save-config", action="store", dest='save_config',
                        help="Save current configuration with the specified name")
    mode_group.add_argument("--create-config", action="store_true", dest='create_config',
                        help="Create a default configuration file")
    
    # Main arguments
    target_group = parser.add_argument_group('Targets')
    target_group.add_argument('-f', "--file", action="store", dest='file',
                        help="File with a list of domains to verify.")
    target_group.add_argument('-d', "--domain", action="store", dest='domain',
                        help="Single domain to verify.")
    target_group.add_argument('-c', "--common", action="store_true", dest='common',
                        help="Common TLDs")
    target_group.add_argument('-t', "--test", action="store_true", dest='test',
                        help="Send a test email")
    target_group.add_argument("--all", action="store_true", dest='all',
                        help="Perform all available checks (equivalent to --profile full)")
    
    # Email sending arguments
    email_group = parser.add_argument_group('Email Options')
    email_group.add_argument('-e', "--email", action="store", dest='email',
                        help="Send an email to this address to test email spoofing.")
    email_group.add_argument('-s', "--smtp", action="store", dest='smtp',
                        help="Use a custom SMTP server to send a test email. Default: 127.0.0.1")
    email_group.add_argument('-a', "--attachment", action="store", dest='attachment',
                        help="Path to file to attach with the email")
    email_group.add_argument("--subject", action="store", dest='subject',
                        help="Email message subject")
    email_group.add_argument("--template", action="store", dest='template',
                        help="HTML template for the message body")
    email_group.add_argument("--sender", action="store", dest='sender',
                        help="Sender email, default <test@domain.tld>")
    
    # Advanced SPF analysis options
    spf_group = parser.add_argument_group('SPF Analysis')
    spf_group.add_argument("--deep-spf", action="store_true", dest='deep_spf',
                        help="Perform deep and recursive SPF analysis to detect issues in the include chain")
    spf_group.add_argument("--spf-details", action="store_true", dest='spf_details',
                        help="Show complete details of SPF analysis")
    spf_group.add_argument("--max-lookups", action="store", dest='max_lookups', type=int, default=10,
                        help="Maximum number of DNS lookups to perform in recursive SPF analysis (default: 10)")
    
    # Advanced DKIM analysis options
    dkim_group = parser.add_argument_group('DKIM Analysis')
    dkim_group.add_argument("--check-dkim", action="store_true", dest='check_dkim',
                        help="Verify the domain's DKIM configuration")
    dkim_group.add_argument("--dkim-selectors", action="store", dest='dkim_selectors',
                        help="List of DKIM selectors to verify, comma-separated (default: common selectors are used)")
    dkim_group.add_argument("--check-alignment", action="store_true", dest='check_alignment',
                        help="Verify DKIM alignment with mail servers")
    dkim_group.add_argument("--dkim-key-min-size", action="store", dest='dkim_key_min_size', type=int, default=1024,
                        help="Minimum recommended size for DKIM keys in bits (default: 1024)")
    
    # Advanced DMARC analysis options
    dmarc_group = parser.add_argument_group('DMARC Analysis')
    dmarc_group.add_argument("--check-dmarc-ext", action="store_true", dest='check_dmarc_ext',
                        help="Perform extended analysis of DMARC configuration")
    dmarc_group.add_argument("--check-external-reports", action="store_true", dest='check_external_reports',
                        help="Verify external DMARC reports configuration")
    dmarc_group.add_argument("--recommend-dmarc", action="store_true", dest='recommend_dmarc',
                        help="Generate recommendations to improve DMARC configuration")
    dmarc_group.add_argument("--dmarc-policy", action="store", dest='dmarc_policy', choices=['none', 'quarantine', 'reject'],
                        help="Recommended DMARC policy for recommendations (default: reject)")
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument("-v", "--verbose", action="count", dest='verbose', default=0,
                        help="Increase verbosity level (can be used multiple times, e.g.: -vv)")
    output_group.add_argument("-q", "--quiet", action="store_true", dest='quiet',
                        help="Quiet mode, only show important results")
    output_group.add_argument("--json", action="store_true", dest='json_output',
                        help="Generate output in JSON format")
    output_group.add_argument("--output", action="store", dest='output_file',
                        help="Save output to a file")

    args = parser.parse_args()
    
    # Handle special options
    if args.list_profiles:
        print(list_profiles())
        sys.exit(0)
    
    if args.all:
        args.check_dkim = True
        args.check_dmarc_ext = True
        args.deep_spf = True
        args.spf_details = True
        args.check_alignment = True
        args.check_external_reports = True
        args.recommend_dmarc = True
    
    # Apply profile if specified
    if args.profile:
        profile = get_profile(args.profile)
        if not profile:
            print(f"Error: Profile '{args.profile}' not found.")
            print(list_profiles())
            sys.exit(1)
    
    # Verify required arguments only if not in interactive mode or using a profile
    if not args.interactive and not args.create_config and not args.profile:
        if (len(sys.argv) == 1) or (not args.file and not args.domain):
            parser.print_help(sys.stderr)
            sys.exit(1)

    return args 