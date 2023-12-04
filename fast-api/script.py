import ssl
import socket
import datetime
import requests
import json
from urllib.parse import urlparse
import dns.resolver
import whois
from datetime import datetime, timedelta

trusted_providers = [
    'Symantec', 'GeoTrust', 'Comodo', 'DigiCert', 'Thawte',
    'GoDaddy', 'Network Solutions', 'RapidSSLonline', 'SSL.com',
    'Entrust Datacard', 'Google Trust Services LLC'
]

class Target:
    def __init__(self, url):
        self.url = url
        self.api_key = 'AIzaSyBNQYvLAjWW8wi5cXoO9ajRGuTedrUmp3E'
        self.http_status = self.check_http_status()
        self.ssl_certificate = self.check_ssl_certificate()
        self.security_headers = self.check_security_headers()
        self.dns_info = self.get_dns_security_info()
        self.whois_info = self.get_whois_security_info()
        self.google_safebrowsing = self.check_url_safety()
        self.score = int(self.calculate_score())

    def check_security_headers(self):
        try:
            response = requests.head(self.url, verify=False)
            headers = response.headers

            security_features = {
                'X-Content-Type-Options': 'X-Content-Type-Options' in headers,
                'X-Frame-Options': 'X-Frame-Options' in headers,
                'Content-Security-Policy': 'Content-Security-Policy' in headers,
                'X-XSS-Protection': 'X-XSS-Protection' in headers,
                'Strict-Transport-Security': 'Strict-Transport-Security' in headers,
                'Referrer-Policy': 'Referrer-Policy' in headers,
                'Feature-Policy': 'Feature-Policy' in headers,
                'Cross-Origin-Resource-Policy': 'Cross-Origin-Resource-Policy' in headers
            }

            return security_features

        except requests.RequestException as e:
            return False
    def check_ssl_certificate(self):
        try:
            parsed_url = urlparse(self.url)
            hostname = parsed_url.netloc.split(':')[0]  # Extracting the hostname from the URL

            context = ssl.create_default_context()
            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
            conn.connect((hostname, 443))
            cert_info = conn.getpeercert()

            # Get current time in UTC
            current_time = datetime.utcnow()

            # Parse certificate dates
            not_before = datetime.strptime(cert_info['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z')

            # Check if certificate is expired
            is_expired = current_time < not_before or current_time > not_after

            # Check if certificate issuer is from a trusted source
            issuer = cert_info['issuer']
            trusted_issuer = any(provider in str(issuer) for provider in trusted_providers)

            # Check if Subject Alternative Name (SAN) includes DNS name from the passed URL
            san = cert_info.get('subjectAltName', [])
            includes_dns_name = any(item[0] == 'DNS' and parsed_url.hostname in item[1] for item in san)

            # Initialize variables for OCSP and CRL reachability checks
            ocsp_reachable = False
            crl_reachable = False

            # Check OCSP URL
            ocsp_url = cert_info.get('OCSP', [])
            if ocsp_url:
                ocsp_response = requests.get(ocsp_url[0])
                ocsp_reachable = ocsp_response.status_code == 200

            # Check CRL URL
            crl_url = cert_info.get('crlDistributionPoints', [])
            if crl_url:
                crl_response = requests.get(crl_url[0])
                crl_reachable = crl_response.status_code == 200

            # Prepare dictionary with SSL attributes including OCSP and CRL checks
            ssl_attributes = {
                'SSL_Validity': not is_expired,
                'SSL_Trusted_Issuer': trusted_issuer,
                'SSL_SAN_Includes_DNS': includes_dns_name,
                'OCSP_Reachable': ocsp_reachable,
                'CRL_Reachable': crl_reachable
            }

            return ssl_attributes

        except ssl.SSLError as ssl_err:
            print(f"SSL Error: {ssl_err}")
            return False

        except requests.RequestException as req_err:
            print(f"Request Error: {req_err}")
            return False

        except Exception as e:
            print(f"Unexpected Error: {e}")
            return False
    
    def check_http_status(self):
        try:
            response = requests.get(self.url, verify=False)
            status_code = response.status_code

            http_status_attributes = {
                'HTTP_Status_Code': status_code,
                'HTTP_OK': status_code == 200,
                'HTTP_Not_Found': status_code == 404,
                'HTTP_Internal_Server_Error': status_code == 500,
                'HTTP_Moved_Permanently': status_code == 301,
                'HTTP_Found_Temporary_Redirect': status_code == 302 or status_code == 307,
                'HTTP_Unauthorized': status_code == 401,
                'HTTP_Forbidden': status_code == 403,
                'HTTP_Method_Not_Allowed': status_code == 405,
                'HTTP_Service_Unavailable': status_code == 503,
                'HTTP_Gateway_Timeout': status_code == 504,
                'HTTP_Too_Many_Requests': status_code == 429
            }

            return http_status_attributes

        except requests.RequestException as e:
            return False

    def get_dns_security_info(self):
        dns_security_info = {
            'Has_A_Record': False,
            'Has_MX_Record': False,
            'Has_TXT_Record': False,
            'Has_PTR_Record': False,
            'Has_CNAME_Record': False,
            'Has_SOA_Record': False,
            'Has_CAA_Record': False,
            'DNSSEC_Enabled': False
        }

        try:
            domain = self.url.split('//')[-1].split('/')[0]

            dns_records_a = dns.resolver.resolve(domain, 'A')
            dns_security_info['Has_A_Record'] = True

            dns_records_mx = dns.resolver.resolve(domain, 'MX')
            dns_security_info['Has_MX_Record'] = True

            dns_records_txt = dns.resolver.resolve(domain, 'TXT')
            dns_security_info['Has_TXT_Record'] = True

            dns_records_ptr = dns.resolver.resolve(dns_records_a[0].address, 'PTR')
            dns_security_info['Has_PTR_Record'] = True

            dns_records_cname = dns.resolver.resolve(domain, 'CNAME')
            dns_security_info['Has_CNAME_Record'] = True

            dns_records_soa = dns.resolver.resolve(domain, 'SOA')
            dns_security_info['Has_SOA_Record'] = True

            dns_records_caa = dns.resolver.resolve(domain, 'CAA')
            dns_security_info['Has_CAA_Record'] = True

            try:
                dns_records_ds = dns.resolver.resolve(domain, 'DS')
                dns_security_info['DNSSEC_Enabled'] = True
            except dns.resolver.NoAnswer:
                dns_security_info['DNSSEC_Enabled'] = False

        except dns.resolver.NXDOMAIN:
            dns_security_info['Has_A_Record'] = False

        except Exception as e:
            pass

        return dns_security_info

    def get_whois_security_info(self):
        reputed_registrars = [
            'IONOS', 'DreamHost', 'Porkbun', 'Namecheap', 'NameSilo',
            'Dynadot', 'Google Domains', 'Hover', 'GoDaddy', 'HostGator',
            'Hostinger', 'ernet'
        ]

        whois_security_info = {
            'Reputed_Registrar': False,
            'Valid_Domain': False,
            'Recent_Creation': False,
            'Valid_Expiration': False
        }

        try:
            domain = whois.whois(self.url)

            if domain:
                whois_security_info['Valid_Domain'] = True

                creation_date = domain.creation_date
                if creation_date:
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    days_since_creation = (datetime.now() - creation_date).days
                    if days_since_creation <= 365:
                        whois_security_info['Recent_Creation'] = True

                expiration_date = domain.expiration_date[0]
                if expiration_date and expiration_date > datetime.now():
                    whois_security_info['Valid_Expiration'] = True

                registrar = domain.registrar
                if registrar:
                    registrar_lower = registrar.lower()
                    for reputed_registrar in reputed_registrars:
                        if reputed_registrar.lower() in registrar_lower:
                            whois_security_info['Reputed_Registrar'] = True
                            break

        except Exception as e:
            pass

        return whois_security_info

    def check_url_safety(self):
        try:
            api_url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'

            payload = {
                'client': {
                    'clientId': "YourClientID",
                    'clientVersion': "1.5.2"
                },
                'threatInfo': {
                    'threatTypes': ["MALWARE", "SOCIAL_ENGINEERING", "THREAT_TYPE_UNSPECIFIED", "UNWANTED_SOFTWARE"],
                    'platformTypes': ["ANY_PLATFORM"],
                    'threatEntryTypes': ["URL"],
                    'threatEntries': [
                        {"url": self.url}
                    ]
                }
            }

            headers = {'Content-Type': 'application/json'}
            params = {'key': self.api_key}

            response = requests.post(api_url, params=params, headers=headers, data=json.dumps(payload))

            if response.status_code == 200:
                data = response.json()
                if 'matches' in data and len(data['matches']) > 0:
                    return False
                else:
                    return True

        except Exception as e:
            pass

        return False

    def calculate_score(self):
        severity = {
            'X-Content-Type-Options': 5,
            'X-Frame-Options': 5,
            'Content-Security-Policy': 5,
            'X-XSS-Protection': 5,
            'Strict-Transport-Security': 1,
            'Referrer-Policy': 1,
            'Feature-Policy': 1,
            'Cross-Origin-Resource-Policy': 4,
            'Has_A_Record': 4,
            'Has_MX_Record': 1,
            'Has_TXT_Record': 1,
            'Has_PTR_Record': 1,
            'Has_CNAME_Record': 1,
            'Has_SOA_Record': 1,
            'Has_CAA_Record': 1,
            'DNSSEC_Enabled': 1,
            'SSL_Validity': 5,
            'SSL_Trusted_Issuer': 2,
            'SSL_SAN_Includes_DNS': 1,
            'OCSP_Reachable': 1,
            'CRL_Reachable': 1,
            'Reputed_Registrar': 2,
            'Valid_Domain': 1,
            'Recent_Creation': 1,
            'Valid_Expiration': 2,
            'HTTP_Status_Code': 2,
            'HTTP_OK': 2,
            'HTTP_Not_Found': 2,
            'HTTP_Internal_Server_Error': 2,
            'HTTP_Moved_Permanently': 2
        }

        max_score = sum(severity.values())
        score = 0

        try:
            score = sum(severity[attribute] for attribute in self.security_headers)
        except:
            pass
        try:
            score += sum(severity[attribute] for attribute in self.dns_info)
        except:
            pass
        try:
            score += sum(severity[attribute] for attribute in self.whois_info)
        except:
            pass
        try:
            score += sum(severity[attribute] for attribute in self.ssl_certificate)
        except:
            pass
        try:
            score += sum(severity[attribute] for attribute in self.http_status)
        except:
            pass

        if not self.google_safebrowsing:
            score -= 50

        rating = ((score / max_score) * 10)+4

        return max(0, min(rating, 10))
