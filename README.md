# Honeypot System

> **Work in Progress:** Project is under development.

A distributed honeypot system implemented using Go and Python. This project aims to listen for attacks on decoy network nodes (such as SSH, HTTP, FTP etc.), capture the malicious activity, and analyze the resulting data. 

We host these fake services and capture data from the attacks using Go. The captured events are then transmitted as JSON payloads to our backend, where they are analyzed and visualized using Python.