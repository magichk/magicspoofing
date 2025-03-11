"""
File-based configuration management for MagicSpoofMail
"""

import os
import json
import argparse
from pathlib import Path

# Default path for the configuration file
DEFAULT_CONFIG_PATH = os.path.expanduser("~/.magicspoofmail.json")

def load_config(config_path=None):
    """
    Loads configuration from a JSON file
    
    Args:
        config_path (str, optional): Path to the configuration file. 
                                     If None, the default path is used.
    
    Returns:
        dict: Loaded configuration or an empty dictionary if it couldn't be loaded
    """
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH
    
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_config(config, config_path=None):
    """
    Saves configuration to a JSON file
    
    Args:
        config (dict): Configuration to save
        config_path (str, optional): Path to the configuration file.
                                     If None, the default path is used.
    
    Returns:
        bool: True if saved successfully, False otherwise
    """
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH
    
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(os.path.abspath(config_path)), exist_ok=True)
        
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
        return True
    except Exception:
        return False

def apply_config_to_args(args, config):
    """
    Applies configuration to command line arguments
    
    Args:
        args (argparse.Namespace): Command line arguments
        config (dict): Configuration to apply
    
    Returns:
        argparse.Namespace: Modified arguments
    """
    # Only apply values that are not already defined in the arguments
    for key, value in config.items():
        if hasattr(args, key) and getattr(args, key) is None:
            setattr(args, key, value)
    
    return args

def create_default_config():
    """
    Creates a default configuration file
    
    Returns:
        dict: Default configuration
    """
    config = {
        "smtp": "127.0.0.1",
        "check_dkim": True,
        "check_dmarc_ext": True,
        "deep_spf": True,
        "max_lookups": 10,
        "dkim_key_min_size": 1024,
        "dmarc_policy": "reject",
        "default_profile": "basic"
    }
    
    save_config(config)
    return config

def config_to_args(config):
    """
    Converts a configuration to command line arguments
    
    Args:
        config (dict): Configuration to convert
    
    Returns:
        argparse.Namespace: Command line arguments
    """
    args = argparse.Namespace()
    for key, value in config.items():
        setattr(args, key, value)
    
    return args 