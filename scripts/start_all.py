#!/usr/bin/env python3
"""
Quick start script for Honeypot Security System
"""

import os
import sys

# Add project directory to path
project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_dir)

# Change to project directory
os.chdir(project_dir)

# Run main
from main import main
main()
