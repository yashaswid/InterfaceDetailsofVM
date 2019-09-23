import paramiko
import os.path
import time
import sys
import re
 
def ssh_connection(ip,UserName,Password):
    
    
    #Creating SSH CONNECTION
    try:
              
        #Reading the username from the file
        username = UserName
        password = Password
        print(ip)
        
        #Logging into device
        session = paramiko.SSHClient()
        session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        #Connect to the device using username and password          
        session.connect(ip.rstrip("\n"), username = username, password = password)
        stdin, stdout, stderr = session.exec_command('ip -o addr | awk \'{split($4, a, \"/\"); print $2\" : \"a[1]}\'')
        output_ip = stdout.readlines()
        print("\n")
        length1 = len(output_ip)
        print("The IP address and the Interface Name")
        print("=====================================")
        for i in output_ip:
            print(i)

        stdin, stdout, stderr = session.exec_command('ip -o link | awk \'$2 {print $2, $(NF-2)}\'')
        output_mac = stdout.readlines()
        print("\n")
        length2 = len(output_mac)
        print("The MAC address and the Interface Name")
        print("======================================")
        for i in output_mac:
            print(i) 
           
        #Start an interactive shell session on the router
        connection = session.invoke_shell()	
        
        
        #Checking command output for IOS syntax errors
        router_output = connection.recv(65535)
        
        if re.search(b"% Invalid input", router_output):
            print("* There was at least one IOS syntax error on device {} :(".format(ip))
            
        else:
            print("\nDONE for device {} :)\n".format(ip))
            
        #Test for reading command output
        print(str(router_output) + "\n")
        
        #Closing the connection
        session.close()
     
    except paramiko.AuthenticationException:
        print("* Invalid username or password :( \n* Please check the username/password file or the device configuration.")
        print("* Closing program... Bye!")


def userInput_InterfaceName(ip, interface,UserName,Password):
    try:
        username = UserName
        password = Password
        print(ip)
        
        #Logging into device
        session = paramiko.SSHClient()
        session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        command = "ifconfig " + interface

        #Connect to the device using username and password          
        session.connect(ip.rstrip("\n"), username = username, password = password)
    
        stdin, stdout, stderr = session.exec_command(command)
        output_ip = stdout.readlines()
        print("\n")
        length1 = len(output_ip)
        print("The Information regarding the interface mentioned is displayed below")
        print("====================================================================")
        for i in output_ip:
            print(i)

        #Start an interactive shell session on the router
        connection = session.invoke_shell()	
        
        
        #Checking command output for IOS syntax errors
        router_output = connection.recv(65535)
        
        if re.search(b"% Invalid input", router_output):
            print("* There was at least one IOS syntax error on device {} :(".format(ip))
            
        else:
            print("\nDONE for device {} :)\n".format(ip))
            
        #Test for reading command output
        print(str(router_output) + "\n")
        
        #Closing the connection
        session.close()
     
    except paramiko.AuthenticationException:
        print("* Invalid username or password :( \n* Please check the username/password file or the device configuration.")
        print("* Closing program... Bye!")


def userInput_Mac_Address(ip, Mac_Address_Input, UserName,Password):
    try:
        username = UserName
        password = Password
        print(ip)
        
        #Logging into device
        session = paramiko.SSHClient()
        session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        #Connect to the device using username and password          
        session.connect(ip.rstrip("\n"), username = username, password = password)
        stdin, stdout, stderr = session.exec_command('ip -o addr | awk \'{split($4, a, \"/\"); print $2\" : \"a[1]}\'')
        output_ip = stdout.readlines()
        
        stdin, stdout, stderr = session.exec_command('ip -o link | awk \'$2 {print $2, $(NF-2)}\'')
        output_mac = stdout.readlines()
        
        matching = [s for s in output_mac if Mac_Address_Input in s]
        print("The interface with correspoding MAC address is: ")
        print(matching[0])
        interface = matching[0].split(':')
        print(interface[0])
        interface1 = interface[0]        
        #position = output_mac.index(Mac_Address_Input)
        #print("Mac address Postion: " + position + " " + output_mac[position])
        command = 'nmcli device status | awk \'{print $1,$2}\' | grep ' + interface1
        session.connect(ip.rstrip("\n"), username = username, password = password)
        stdin, stdout, stderr = session.exec_command(command)
        output_type = stdout.readlines()
        print("\n")
        print("The type of interface:")
        print(output_type[0])

        matching1 = [s for s in output_ip if interface1 in s]
        print("The IP with correspoding MAC address is: ")
        print(matching1[0])

        command = "ifconfig " + interface1
        stdin, stdout, stderr = session.exec_command(command)
        complete_interface_information = stdout.readlines()

        print("More information regarding the interface with Mac Address: " + Mac_Address_Input)
        for i in complete_interface_information:
            print(i)
        
        #Start an interactive shell session on the router
        connection = session.invoke_shell()	
        
        
        #Checking command output for IOS syntax errors
        router_output = connection.recv(65535)
        
        if re.search(b"% Invalid input", router_output):
            print("* There was at least one IOS syntax error on device {} :(".format(ip))
            
        else:
            print("\nDONE for device {} :)\n".format(ip))
            
        #Test for reading command output
        print(str(router_output) + "\n")
        
        #Closing the connection
        session.close()
     
    except paramiko.AuthenticationException:
        print("* Invalid username or password :( \n* Please check the username/password file or the device configuration.")
        print("* Closing program... Bye!")		


def userInput_IP_Address(ip, IP_Address_Input,UserName,password):
    try:
        username = UserName
        password = Password
        print(ip)
        
        #Logging into device
        session = paramiko.SSHClient()
        session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        #Connect to the device using username and password          
        session.connect(ip.rstrip("\n"), username = username, password = password)
        stdin, stdout, stderr = session.exec_command('ip -o addr | awk \'{split($4, a, \"/\"); print $2\" : \"a[1]}\'')
        output_ip = stdout.readlines()
        
        stdin, stdout, stderr = session.exec_command('ip -o link | awk \'$2 {print $2, $(NF-2)}\'')
        output_mac = stdout.readlines()
        #print(output_mac)
        
        matching = [s for s in output_ip if IP_Address_Input in s]
        print("\nThe interface with correspoding IP_Address address is: ")
        print(matching[0])
        interface = matching[0].split(':')
        #print(interface[0])
        interface1 = interface[0]

        #position = output_mac.index(Mac_Address_Input)
        #print("Mac address Postion: " + position + " " + output_mac[position])

        command = 'ip -o link | awk \'$2 {print $2, $(NF-2)}\' | grep ' + interface1
       # print(command)
        stdin, stdout, stderr = session.exec_command(command)
        mac_address = stdout.readlines()
        print("The MAC address corresponding the IP address: ")
        print(mac_address[0])

        command = 'nmcli device status | awk \'{print $1,$2}\' | grep ' + interface1
        session.connect(ip.rstrip("\n"), username = username, password = password)
        stdin, stdout, stderr = session.exec_command(command)
        output_type = stdout.readlines()
        print("\n")
        print("The type of interface:")
        print(output_type[0])
     
        command = "ifconfig " + interface1
        stdin, stdout, stderr = session.exec_command(command)
        complete_interface_information = stdout.readlines()

        print("\nMore information regarding the interface with IP Address: " + IP_Address_Input)
        for i in complete_interface_information:
            print(i)
        
        #Start an interactive shell session on the router
        connection = session.invoke_shell()	
        
        
        #Checking command output for IOS syntax errors
        router_output = connection.recv(65535)
        
        if re.search(b"% Invalid input", router_output):
            print("* There was at least one IOS syntax error on device {} :(".format(ip))
            
        else:
            print("\nDONE for device {} :)\n".format(ip))
            
        #Test for reading command output
        print(str(router_output) + "\n")
        
        #Closing the connection
        session.close()
     
    except paramiko.AuthenticationException:
         print("* Invalid username or password :( \n* Please check the username/password file or the device configuration.")
         print("* Closing program... Bye!")

def All_IP_Address(ip,UserName,Password):
    
    
    #Creating SSH CONNECTION
    try:
              
        #Reading the username from the file
        username = UserName
        password = Password
        print(ip)
        
        #Logging into device
        session = paramiko.SSHClient()
        session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        #Connect to the device using username and password          
        session.connect(ip.rstrip("\n"), username = username, password = password)
        stdin, stdout, stderr = session.exec_command('ip -o addr | awk \'{split($4, a, \"/\"); print $2\" : \"a[1]}\'')
        output_ip = stdout.readlines()
        print("\n")
        length1 = len(output_ip)
        print("The IP address and the Interface Name")
        print("=====================================")
        for i in output_ip:
            print(i)

               
        #Start an interactive shell session on the router
        connection = session.invoke_shell()	
        
        
        #Checking command output for IOS syntax errors
        router_output = connection.recv(65535)
        
        if re.search(b"% Invalid input", router_output):
            print("* There was at least one IOS syntax error on device {} :(".format(ip))
            
        else:
            print("\nDONE for device {} :)\n".format(ip))
            
        #Test for reading command output
        print(str(router_output) + "\n")
        
        #Closing the connection
        session.close()
     
    except paramiko.AuthenticationException:
        print("* Invalid username or password :( \n* Please check the username/password file or the device configuration.")
        print("* Closing program... Bye!")


def All_MAC_Address(ip,UserName,Password):
    
    
    #Creating SSH CONNECTION
    try:
              
        #Reading the username from the file
        username = UserName
        password = Password
        print(ip)
        
        #Logging into device
        session = paramiko.SSHClient()
        session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        #Connect to the device using username and password          
        session.connect(ip.rstrip("\n"), username = username, password = password)
        stdin, stdout, stderr = session.exec_command('ip -o link | awk \'$2 {print $2, $(NF-2)}\'')
        output_mac = stdout.readlines()
        print("\n")
        length2 = len(output_mac)
        print("The MAC address and the Interface Name")
        print("======================================")
        for i in output_mac:
            print(i) 
           
        #Start an interactive shell session on the router
        connection = session.invoke_shell()	
        
        
        #Checking command output for IOS syntax errors
        router_output = connection.recv(65535)
        
        if re.search(b"% Invalid input", router_output):
            print("* There was at least one IOS syntax error on device {} :(".format(ip))
            
        else:
            print("\nDONE for device {} :)\n".format(ip))
            
        #Test for reading command output
        print(str(router_output) + "\n")
        
        #Closing the connection
        session.close()
     
    except paramiko.AuthenticationException:
        print("* Invalid username or password :( \n* Please check the username/password file or the device configuration.")
        print("* Closing program... Bye!")


def All_Inf_Type(ip,UserName,Password):
    
    
    #Creating SSH CONNECTION
    try:
              
        #Reading the username from the file
        username = UserName
        password = Password
        print(ip)
        
        #Logging into device
        session = paramiko.SSHClient()
        session.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        #Connect to the device using username and password          
        session.connect(ip.rstrip("\n"), username = username, password = password)
        stdin, stdout, stderr = session.exec_command('nmcli device status | awk \'{print $1,$2}\'')
        output_type = stdout.readlines()
        print("\n")
        length2 = len(output_type)
        print("The Interface TYPE")
        print("==================")
        for i in output_type:
            print(i) 
           
        #Start an interactive shell session on the router
        connection = session.invoke_shell()	
        
        
        #Checking command output for IOS syntax errors
        router_output = connection.recv(65535)
        
        if re.search(b"% Invalid input", router_output):
            print("* There was at least one IOS syntax error on device {} :(".format(ip))
            
        else:
            print("\nDONE for device {} :)\n".format(ip))
            
        #Test for reading command output
        print(str(router_output) + "\n")
        
        #Closing the connection
        session.close()
     
    except paramiko.AuthenticationException:
        print("* Invalid username or password :( \n* Please check the username/password file or the device configuration.")
        print("* Closing program... Bye!")


#Main Program

print("Program to Display the IP interface details of the machine")
counter = 1
while (counter == 1):
    print("Choose one of the option below:")
    print("1. Display the corresponding interface details when IP is given as input by the user.")
    print("2. Display the corresponding interface details when MAC is given as input by the user.")
    print("3. Display all the IP addresses with respective interface name associated to the linux machine.")
    print("4. Display all the MAC addresses with respective interface name associated to the linux machine.")
    print("5. Display Type of all the interface associated with the machine")
    print("6. Exit")
    user_input = input("Enter one of the option mentioned above:")

    
    if user_input == "3":
        Ip_Address = input("Enter the IP address of the Server to login to: ")
        UserName = input("Enter the User of the Server: ")
        Password = input("Enter the Password of the Server: ")
        All_IP_Address(Ip_Address,UserName,Password)
        counter = 1
        
    if user_input == "4":
        Ip_Address = input("Enter the IP address of the Server to login to: ")
        UserName = input("Enter the User of the Server: ")
        Password = input("Enter the Password of the Server: ")
        All_MAC_Address(Ip_Address,UserName,Password)
        counter = 1
        
    if user_input == "1":
        Ip_Address = input("Enter the IP address of the Server to login to: ")
        UserName = input("Enter the User of the Server: ")
        Password = input("Enter the Password of the Server: ")
        IP_Address_Input = input("Enter the IP Address: ")
        userInput_IP_Address(Ip_Address, IP_Address_Input,UserName,Password)
        counter = 1

    if user_input == "2":
        Ip_Address = input("Enter the IP address of the Server to login to: ")
        UserName = input("Enter the User of the Server: ")
        Password = input("Enter the Password of the Server: ")
        Mac_Address_Input = input("Enter the MAC address:")
        userInput_Mac_Address(Ip_Address,Mac_Address_Input,UserName,Password)
        counter = 1

    if user_input == "5":
        Ip_Address = input("Enter the IP address of the Server to login to: ")
        UserName = input("Enter the User of the Server: ")
        Password = input("Enter the Password of the Server: ")
        All_Inf_Type(Ip_Address,UserName,Password)
        counter = 1

    if user_input == "6":
        print("Exiting from the program")
        counter = 0
    
    if user_input > "6":
        print("Enter correct option seeing the menu")
        counter = 1
    #ssh_connection(Ip_Address)
    #Interface_Name = input("Enter the interface Name which details needs to be displayed: ")
    #userInput_InterfaceName(Ip_Address,Interface_Name)
    #Mac_Address_Input = input("Enter the MAC address:")
    #userInput_Mac_Address(Ip_Address,Mac_Address_Input,UserName,Password)
    



