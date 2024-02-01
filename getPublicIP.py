# -*- coding: utf-8 -*-
"""
Created on Thu Nov  2 01:53:55 2023

@author: ljste
"""

import requests

def get_public_ip():
    try:
        response = requests.get("https://httpbin.org/ip")
        if response.status_code == 200:
            return response.json()["origin"]
        else:
            return "Failed to retrieve IP"
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    public_ip = get_public_ip()
    print(f"Public IP Address: {public_ip}")
