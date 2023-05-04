from fastapi import FastAPI, HTTPException
import os
import subprocess
import re
import mysql.connector
import socket
from pydantic import BaseModel
from typing import Optional
from typing import List
import asyncio
# from concurrent.futures import ThreadPoolExecutor


app = FastAPI()


# ------------------  FastApi endpoint define ------------------------- # 
@app.get("/multi-api")
async def run_multi_api(ip_address: str):
    # create a list of async functions to run concurrently
    tasks = [
        asyncio.create_task(perform_port_scan(ip_address)),
        asyncio.create_task(get_vulnerabilities(ip_address)),
        asyncio.create_task(get_phishing(ip_address)),
        asyncio.create_task(get_traffic(ip_address)),
    ]

    # await all the tasks using asyncio.gather()
    results = await asyncio.gather(*tasks)

    return {"results": results}

@app.post("/create-user(register)")
async def create_user(username: str, name: str, password: str, email: str):
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="root",
        database="mydatabase"
    )
    cursor = conn.cursor()

    cursor.execute(f"SELECT id FROM users WHERE username = '{username}'")
    result = cursor.fetchone()
    if result:
        conn.close()
        raise HTTPException(status_code=400, detail="Username already exists")

    query = "INSERT INTO users (username, name, password, email) VALUES (%s, %s, %s, %s)"
    values = (username, name, password, email)
    cursor.execute(query, values)
    conn.commit()
    conn.close()
    return {"message": "User created successfully"}


@app.get("/login")
async def perform_login(username: str, password: str):
    result = login(username, password)
    return {"result": "success" if result else "failure"}


@app.get("/list-connected-device")
async def get_device_info():
    result = get_devices()
    return {"device_info": result}


class IpMac(BaseModel):
    ip: str
    mac: str
@app.post("/insert_known")
async def insert_known(ip_mac: IpMac):
    data = insert_ip_mac(ip_mac)
    data2 = insert_ip_mac_report(ip_mac)
    run_multi_api(ip_address)

    return data2

@app.get("/port-scan")
async def perform_port_scan(ip_address: str):
    result = port_scan(ip_address)
    return result

@app.get("/vulnerabilities/{ip_address}")
async def get_vulnerabilities(ip_address: str):
    return scan_vulnerabilities(ip_address)

@app.get("/phishing")
async def get_phishing(ip_address: str):
    data = phising_attack(ip_address)
    return data


@app.get("/traffic")
async def get_traffic(ip_address: str):
    data = traffic_analyser(ip_address)
    return data



# Define the route for the API
@app.get("/knownTable")
async def get_all_records():
    data = get_knownTable()
    return data

@app.get("/all-in-one")
async def all_in_one(ip_address: str):
    
    # Submit all four functions for execution
    future_port_scan = port_scan(ip_address)
    future_vulnerabilities = scan_vulnerabilities(ip_address)
    future_phishing = phising_attack(ip_address)
    future_traffic = traffic_analyser(ip_address)
    # Wait for all functions to complete and get their results
    result_port_scan = future_port_scan.result()
    result_vulnerabilities = future_vulnerabilities.result()
    result_phishing = future_phishing.result()
    result_traffic = future_traffic.result()

    return {
        "open_ports": result_port_scan,
        "vulnerabilities": result_vulnerabilities,
        "phishing": result_phishing,
        "traffic": result_traffic,
    }

# ------------------------------ Functions for API's ------------------------------ #

def get_devices():
    command = "arp-scan --localnet | awk '{print $1\",\"$2}' | tail -n +3"
    result = subprocess.check_output(command, shell=True).decode('utf-8')
    devices = []
    for line in result.split('\n'):
        fields = line.split(',')
        if len(fields) != 2:
            continue
        ip_address = fields[0]
        mac_address = fields[1]
        # Check if the IP or MAC address is already present in the devices list
        if any(device['ip_address'] == ip_address or device['mac_address'] == mac_address for device in devices):
            continue
        # Validate the IP and MAC address formats
        if not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip_address) or not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac_address):
            continue
        devices.append({'ip_address': ip_address, 'mac_address': mac_address})
    return devices

def port_scan(ip_address):
    openports=0
    update_db(ip_address,openports,'open_ports')
    output = os.popen(f"nmap -Pn -T4 -oN {ip_address}_ports {ip_address}").read()
    port_list = re.findall(r"\d+/tcp\s", output)
    
    openports = len(port_list) 
    update_db(ip_address,openports,'open_ports')
    update_record(ip_address, openports,'open_ports')
    return port_list



def login(username, password):
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="root",
        database="mydatabase"
    )
    cursor = conn.cursor()
    # cursor.execute("CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255), password VARCHAR(255))")
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
    result = cursor.fetchone()
    conn.close()
    return result


def scan_vulnerabilities(ip_address):
    vuln_count = 0 
    update_db(ip_address,vuln_count,'vuln_found')
    command = f"nmap -sV --script vuln {ip_address}"
    process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()
    if error:
        return {"error": error.decode("utf-8")}
    vulnerabilities = []
    lines = output.decode("utf-8").splitlines()
    for line in lines:
        if "VULNERABLE" in line:
            vulnerabilities.append(line.strip())
    vuln_count = len(vulnerabilities)
    update_db(ip_address,vuln_count,'vuln_found')
    return {"vulnerabilities": vulnerabilities}



#  Define the function to insert IP and MAC addresses into the database
def insert_ip_mac(ip_mac: IpMac):
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="root",
            database="mydatabase"
        )
        cursor = conn.cursor()
        sql = "INSERT INTO knownTable (ipaddress, macaddress) VALUES (%s, %s)"
        val = (ip_mac.ip, ip_mac.mac)
        cursor.execute(sql, val)
        conn.commit()
        conn.close()
        return {"message": "IP and MAC address inserted successfully"}

    except mysql.connector.Error as e:
        return {"error": "Database error: " + str(e)}


def insert_ip_mac_report(ip_mac: IpMac):
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="root",
            database="mydatabase"
        )
        cursor = conn.cursor()
        sql = "INSERT INTO Report (ipaddress, macaddress) VALUES (%s, %s)"
        val = (ip_mac.ip, ip_mac.mac)
        cursor.execute(sql, val)
        conn.commit()
        conn.close()
        return {"message": "IP and MAC address "}

    except mysql.connector.Error as e:
        return {"error": "Database error: " + str(e)}


def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    ip_address = s.getsockname()[0]
    s.close()
    return ip_address

ip_address = get_ip_address()


def get_knownTable():

    mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="root",
    database="mydatabase"
    )
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM knownTable")
    rows = mycursor.fetchall()
    data = []
    for row in rows:
        data.append({
            "macaddress": row[0],
            "ipaddress": row[1],
            "open_ports": row[2],
            "vuln_found": row[3],
            "phishing_status": row[4],
            "traffic_status": row[5]
        })
    
    return data


def phising_attack(ip):
    phisingstatus="pass"
    update_db(ip, phisingstatus,'phishing_status')
    return {"Dummy Data Updated"}

def traffic_analyser(ip):
    trafficstatus="safe"
    update_db(ip, trafficstatus,'traffic_status')
    return {"Dummy Data Updated"}

def update_db(ip, value , column):
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="root",
        database="mydatabase"
    )
    cursor = conn.cursor()
    update_query = f"UPDATE knownTable SET {column} = %s WHERE ipaddress = %s"
    cursor.execute(update_query, (value, ip))
    conn.commit()
    conn.close()
    print(f"Updated vuln_found to for IP address {ip}")

def update_record(ip, value , column):
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="root",
        database="mydatabase"
    )
    cursor = conn.cursor()
    update_query = f"UPDATE Report SET {column} = %s WHERE ipaddress = %s"
    cursor.execute(update_query, (value, ip))
    conn.commit()
    conn.close()
    print(f"Updated vuln_found to for IP address {ip}")


# Check if the users table exists and create it if it doesn't
def create_table():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="root",
        database="mydatabase"
    )
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) UNIQUE, name VARCHAR(255), password VARCHAR(255), email VARCHAR(255))")
    cursor.execute("CREATE TABLE IF NOT EXISTS knownTable (macaddress VARCHAR(25) NOT NULL, ipaddress VARCHAR(15) NOT NULL, open_ports INT, vuln_found INT, phishing_status ENUM('pass', 'fail'), traffic_status ENUM('safe', 'suspicious', 'dangerous'), PRIMARY KEY (macaddress, ipaddress))")
    cursor.execute("CREATE TABLE IF NOT EXISTS Report (macaddress VARCHAR(25) NOT NULL, ipaddress VARCHAR(15) NOT NULL, open_ports VARCHAR(500), vuln_found  VARCHAR(130), phishing_status  VARCHAR(130), traffic_status  VARCHAR(130), PRIMARY KEY (macaddress, ipaddress))")
    conn.close()
create_table()




