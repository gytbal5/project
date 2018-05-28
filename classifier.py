from scapy.all import *
from operator import attrgetter
import pyshark
import numpy
import os
import tkinter as tk
from tkinter import messagebox
import pandas as pd
import pandas
from sklearn import model_selection
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier

class Classifier:
    while 1:

        print(pyshark.tshark.tshark.get_tshark_interfaces())
        file = "pyshark.pcap"

        """time.sleep(5)
        try:
            os.remove(file)
        except FileNotFoundError:
            print("File not found")"""
        cap = pyshark.LiveCapture(interface='4', output_file=file)
        cap.sniff(timeout=20)

        """time.sleep(5)
        try:
            os.remove("test2.csv")
        except:
            print("File not found")"""

        df = pd.DataFrame(columns=['packet_cnt', 'packet_cnt_up', 'packet_cnt_down', 'intarv_time_med',
                                   'intarv_time_max',
                                   'intarv_time_min', 'intarv_time_med_up', 'intarv_time_max_up',
                                   'intarv_time_min_up',
                                   'intarv_time_med_down', 'intarv_time_max_down', 'intarv_time_min_down',
                                   'bytes_payload_l4_med', 'bytes_payload_l4_max', 'bytes_payload_l4_min',
                                   'bytes_payload_range',
                                   'bytes_payload_l4_med_up', 'bytes_payload_l4_max_up',
                                   'bytes_payload_l4_min_up', 'bytes_payload_range_up',
                                   'bytes_payload_l4_med_down', 'bytes_payload_l4_max_down',
                                   'bytes_payload_l4_min_down', 'bytes_payload_range_down', 'duration_flow',
                                   'duration_flow_up',
                                   'duration_flow_down', 'changes_bulktrans_mode', 'duration_bulkmode',
                                   'duration_bulkmode_up', 'duration_bulkmode_down', 'qouta_bulkmode',
                                   'qouta_bulkmode_upstream', 'qouta_bulkmode_downstream',
                                   'time_in_idle_mode', 'time_in_idle_mode_upstream', 'time_in_idle_mode_downstream',
                                   'time_in_idle_mode_qouta', 'time_in_idle_mode_qouta_up',
                                   'time_in_idle_mode_qouta_down', 'website'])

        file = rdpcap('pyshark.pcap')
        upstream = []
        downstream = []
        ipadress = '192.168.0.237'
        sessions = file[TCP].sessions()
        sessionsNew = []
        website = 3
        limit = 20
        for k, v in sessions.items():
            up = 0
            down = 0
            for packet in v:
                if packet['IP'].src == ipadress:
                    up += 1
                if packet['IP'].dst == ipadress:
                    down += 1

            if up != 0:
                upstream.append(v)
                print(up)
            if down != 0:
                downstream.append(v)
                print(down)
        if len(upstream) < len(downstream):
            min = len(upstream)
        else:
            min = len(downstream)
        for i in range(0, min):
            newArray = []
            newArray = upstream[i] + downstream[i]
            sessionsNew.append(newArray)
        wholesessiontime = 0
        for session in sessionsNew:
            session.sort(key=attrgetter('time'))
        test = 0
        sessionend = 0
        sesijosnr = 0
        for v in sessionsNew:
            wholesession = []
            sessionup = []
            sessiondown = []
            for packet in v:
                wholesession.append(packet)
                if packet['IP'].src == ipadress:
                    sessionup.append(packet)
                if packet['IP'].dst == ipadress:
                    sessiondown.append(packet)
                wholesessiontime += packet.time

            sessionend += 1
            upcounter = 0  # Upstream packetu counteris
            downcounter = 0  # Downstream packetu counteris
            packetcount = 0  # visu packetu counteris
            intarvu = []
            intarvd = []
            intarv = []  # intervalai laiko
            intarvup = []  # Upstream intervalai
            intarvdown = []  # Downstream intervalai
            payloaddown = []  # L4 Payload dowstream
            payloadup = []  # L4 payload upstream
            payload = []  # L4 payload apskritai
            time = 0  # Visas laikas
            timeup = 0  # Upstream laikas
            timedown = 0  # Downstream laikas

            wholetime = 0
            temporarytime = 0
            changes = 0
            temporarychanges = 0
            wholetimeup = 0
            wholetimedown = 0

            for packet in v:
                if packet['IP'].src == ipadress:
                    upcounter += 1
                if packet['IP'].dst == ipadress:
                    downcounter += 1
            packetcount = len(v)
            for i in range(0, len(wholesession) - 1):
                intarv.append(wholesession[i + 1].time - wholesession[i].time)
            intarv.sort()  # Rikiuojami intervalai, nes mediana skaiciuojasi i� surikiuotu duomenu
            half = int(round(len(intarv) / 2))  # Vidurys
            if half == 0:
                median = 0
                maxintarv = 0
                minintarv = 0
            else:
                median = intarv[half]
                # 5 punktas
                maxintarv = intarv[len(intarv) - 1]  # Pats did�iausias intervalas
                # 6punktas
                minintarv = intarv[0]
            # 7punktas pasiruosimas
            #     for i in range(0, len(sessionup)):
            #        if (packets[i]['IP'].src == ipadress):
            #           intarvu.append(packets[i])
            #  for i in range(0, packetcount):
            #     if (packets[i]['IP'].dst == ipadress):
            #        intarvd.append(packets[i])
            # toliau reikia susiskaiciuot intervalus ir ie�kot 7... punktu
            for i in range(0, len(sessionup) - 1):
                intarvup.append(sessionup[i + 1].time - sessionup[i].time)
            for i in range(0, len(sessiondown) - 1):
                intarvdown.append((sessiondown[i + 1].time - sessiondown[i].time))
            intarvup.sort()
            intarvdown.sort()
            # 7 punktas
            half = int(round(len(intarvup) / 2))
            if half == 0:
                upstreamintarvmin = 0
                upstreamintarvmax = 0
                upstreamintarvmedian = 0
            else:
                upstreamintarvmedian = intarvup[half]
                # 8 punktas
                upstreamintarvmin = intarvup[0]
                # 9 punktas
                upstreamintarvmax = intarvup[len(intarvup) - 1]
                # 10 punktas
            half = int(round(len(intarvdown) / 2))
            # print(half)
            # print(len(intarvdown))
            if half == 0:
                downstreamintarvmedian = 0
                downstreamintarvmin = 0
                downstreaintarvmax = 0
            else:
                downstreamintarvmedian = intarvdown[half]
                # 11 punktas
                downstreamintarvmin = intarvdown[0]
                # 12 punktas
                downstreaintarvmax = intarvdown[len(intarvdown) - 1]
            for packet in v:
                if TCP in packet:
                    payload.append(len(packet[TCP].payload))
                    if packet['IP'].src == ipadress:
                        payloadup.append((len(packet[TCP].payload)))
                    if packet['IP'].dst == ipadress:
                        payloaddown.append((len(packet[TCP].payload)))
                if UDP in packet:
                    payload.append(len(packet[UDP].payload))
                    if packet['IP'].src == ipadress:
                        payloadup.append((len(packet[UDP].payload)))
                    if packet['IP'].dst == ipadress:
                        payloaddown.append((len(packet[UDP].payload)))
            print("PAYLOAD: {} PAYLOADDOWN: {} PAYLOADUP: {}".format(len(payload), len(payloaddown), len(payloadup)))
            payload.sort()
            payloaddown.sort()
            payloadup.sort()
            half = int(round(len(payload) / 2))
            medianpayload = payload[half]
            maximumpayload = payload[-1]
            minimumpayload = payload[0]  # 0?????
            maxminusmin = maximumpayload - minimumpayload  # max-0=max!!!!!

            if len(payloadup) == 0:
                medianuppayload = 0
                maxuppayload = 0
                minuppayload = 0
                upmaxminusmin = 0
            else:
                half = int(round(len(payloadup) / 2))
                medianuppayload = payloadup[half]
                maxuppayload = payloadup[len(payloadup) - 1]
                minuppayload = payloadup[0]  # 0?????
                upmaxminusmin = maxuppayload - minuppayload  # max-0=max!!!!!

            if len(payloaddown) == 0:
                medianpayloaddown = 0
                maxdownpayload = 0
                mindownpayload = 0
                downmaxminusmin = 0
            else:
                half = int(round(len(payloaddown) / 2))
                print("HALF {} payloaddownLength: {}".format(half, len(payloaddown)))
                medianpayloaddown = payloaddown[half]
                maxdownpayload = payloaddown[-1]
                mindownpayload = payloaddown[0]
                downmaxminusmin = maxdownpayload - mindownpayload

            for packet in v:
                time += packet.time
                if packet['IP'].src == ipadress:
                    timeup += packet.time
                if packet['IP'].dst == ipadress:
                    timedown += packet.time

            for i in range(0, len(wholesession) - 1):
                if (wholesession[i]['IP'].src == wholesession[i + 1]['IP'].src):
                    temporarychanges += 1
                    temporarytime += wholesession[i].time
                else:
                    temporarychanges = 0
                    temporarytime = 0
                if temporarychanges == 3:
                    changes += 1
                    wholetime += temporarytime
            temporarytime = 0
            wholetimeup = 0
            for i in range(0, len(sessionup) - 1):
                if (sessionup[i]['IP'].src == sessionup[i + 1]['IP'].src):
                    temporarychanges += 1
                    temporarytime += sessionup[i].time
                else:
                    temporarychanges = 0
                    temporarytime = 0
                if temporarychanges == 3:
                    wholetimeup += temporarytime
            temporarytime = 0
            # 31 punktas
            for i in range(0, len(sessiondown) - 1):
                if (sessiondown[i]['IP'].src == sessiondown[i + 1]['IP'].src):
                    temporarychanges += 1
                    temporarytime += sessiondown[i].time
                else:
                    temporarychanges = 0
                    temporarytime = 0
                if temporarychanges == 3:
                    wholetimedown += temporarytime
            wholesessiontimeup = 0
            wholesessiontimedown = 0
            for packet in sessionup:
                wholesessiontimeup += packet.time
            for packet in sessiondown:
                wholesessiontimedown += packet.time
            wholetimequote = wholetime / wholesessiontime * 100
            wholetimequoteup = wholetimeup / wholesessiontimeup * 100
            wholetimequotedown = wholetimedown / wholesessiontimedown * 100

            timeidle = 0
            timeidleup = 0
            timeidledown = 0
            for interval in intarv:
                if interval >= 2:
                    timeidle += interval
            for interval in intarvup:
                if interval >= 2:
                    timeidleup += interval
            for interval in intarvdown:
                if interval >= 2:
                    timeidledown += interval

            idletimeqouta = timeidle / wholesessiontime * 100
            idletimeqoutaup = timeidleup / wholesessiontimeup * 100
            idletimeqoutadown = timeidledown / wholesessiontimedown * 100

            print("Paketai visi{}".format(packetcount))
            print("Upstream paketai{}".format(upcounter))
            print("Downstream paketai{}".format(downcounter))
            print("mediana {}".format(median))
            print("Max interval {}".format(maxintarv))
            print("Min interval {}".format(minintarv))
            print("{} {}".format(upstreamintarvmedian, "Median"))
            print(upstreamintarvmin)
            print(downstreaintarvmax)
            print(downstreamintarvmedian)
            print(downstreamintarvmin)
            print(medianpayload)
            print(maximumpayload)
            print(minimumpayload)
            print(maxminusmin)
            print("median {}   max {}    min {}    max-min {}    ".format(medianuppayload, maxuppayload, minuppayload,
                                                                          upmaxminusmin))
            print("median {}   max {}    min {}    max-min {}    ".format(medianpayloaddown, maxdownpayload,
                                                                          mindownpayload,
                                                                          downmaxminusmin))
            print("time {} uptime {} downtime {}".format(time, timeup, timedown))
            print("changes: {} time: {}".format(changes, wholetime))
            print("UPSTREAM time: {}".format(wholetimeup))
            print("DOWNSTREAM time: {}".format(wholetimedown))
            print()
            print(sesijosnr)
            sesijosnr += 1
            print(wholetimequote)
            print(wholetimequoteup)
            print(wholetimequotedown)
            print(timeidle)
            print(timeidleup)
            print(timeidledown)
            print(idletimeqouta)
            print(idletimeqoutaup)
            print(idletimeqoutadown)
            print()

            df = df.append({'packet_cnt': packetcount,
                            'packet_cnt_up': upcounter,
                            'packet_cnt_down': downcounter,
                            'intarv_time_med': median,
                            'intarv_time_max': maxintarv,
                            'intarv_time_min': minintarv,
                            'intarv_time_med_up': upstreamintarvmedian,
                            'intarv_time_max_up': upstreamintarvmax,
                            'intarv_time_min_up': upstreamintarvmin,
                            'intarv_time_med_down': downstreamintarvmedian,
                            'intarv_time_max_down': downstreaintarvmax,
                            'intarv_time_min_down': downstreamintarvmin,
                            'bytes_payload_l4_med': medianpayload,
                            'bytes_payload_l4_max': maximumpayload,
                            'bytes_payload_l4_min': minimumpayload,
                            'bytes_payload_range': maxminusmin,
                            'bytes_payload_l4_med_up': medianuppayload,
                            'bytes_payload_l4_max_up': maxuppayload,
                            'bytes_payload_l4_min_up': minuppayload,
                            'bytes_payload_range_up': upmaxminusmin,
                            'bytes_payload_l4_med_down': medianpayloaddown,
                            'bytes_payload_l4_max_down': maxdownpayload,
                            'bytes_payload_l4_min_down': mindownpayload,
                            'bytes_payload_range_down': downmaxminusmin,
                            'duration_flow': time,
                            'duration_flow_up': timeup,
                            'duration_flow_down': timedown,
                            'changes_bulktrans_mode': changes,
                            'duration_bulkmode': wholetime,
                            'duration_bulkmode_up': wholetimeup,
                            'duration_bulkmode_down': wholetimedown,
                            'qouta_bulkmode': wholetimequote,
                            'qouta_bulkmode_upstream': wholetimequoteup,
                            'qouta_bulkmode_downstream': wholetimequotedown,
                            'time_in_idle_mode': timeidle,
                            'time_in_idle_mode_upstream': timeidleup,
                            'time_in_idle_mode_downstream': timeidledown,
                            'time_in_idle_mode_qouta': idletimeqouta,
                            'time_in_idle_mode_qouta_up': idletimeqoutaup,
                            'time_in_idle_mode_qouta_down': idletimeqoutadown,
                            'website': website}, ignore_index=True)

        df.to_csv("test2.csv", mode='a', encoding='utf-8', index=False)

        ##DUOMENYS
        data = pandas.read_csv("fit.csv")
        input_data = data[['packet_cnt', 'packet_cnt_up', 'packet_cnt_down', 'intarv_time_med',
                           'intarv_time_max',
                           'intarv_time_min', 'intarv_time_med_up', 'intarv_time_max_up',
                           'intarv_time_min_up',
                           'intarv_time_med_down', 'intarv_time_max_down', 'intarv_time_min_down',
                           'bytes_payload_l4_med', 'bytes_payload_l4_max', 'bytes_payload_l4_min',
                           'bytes_payload_range',
                           'bytes_payload_l4_med_up', 'bytes_payload_l4_max_up',
                           'bytes_payload_l4_min_up', 'bytes_payload_range_up',
                           'bytes_payload_l4_med_down', 'bytes_payload_l4_max_down',
                           'bytes_payload_l4_min_down', 'bytes_payload_range_down', 'duration_flow',
                           'duration_flow_up',
                           'duration_flow_down', 'changes_bulktrans_mode', 'duration_bulkmode',
                           'duration_bulkmode_up', 'duration_bulkmode_down', 'qouta_bulkmode',
                           'qouta_bulkmode_upstream', 'qouta_bulkmode_downstream',
                           'time_in_idle_mode', 'time_in_idle_mode_upstream', 'time_in_idle_mode_downstream',
                           'time_in_idle_mode_qouta', 'time_in_idle_mode_qouta_up',
                           'time_in_idle_mode_qouta_down']]
        output_data = data[['website']]
        test = pandas.read_csv("test2.csv")  # test2 twit, test1 fb
        testav = test[['packet_cnt', 'packet_cnt_up', 'packet_cnt_down', 'intarv_time_med',
                       'intarv_time_max',
                       'intarv_time_min', 'intarv_time_med_up', 'intarv_time_max_up',
                       'intarv_time_min_up',
                       'intarv_time_med_down', 'intarv_time_max_down', 'intarv_time_min_down',
                       'bytes_payload_l4_med', 'bytes_payload_l4_max', 'bytes_payload_l4_min',
                       'bytes_payload_range',
                       'bytes_payload_l4_med_up', 'bytes_payload_l4_max_up',
                       'bytes_payload_l4_min_up', 'bytes_payload_range_up',
                       'bytes_payload_l4_med_down', 'bytes_payload_l4_max_down',
                       'bytes_payload_l4_min_down', 'bytes_payload_range_down', 'duration_flow',
                       'duration_flow_up',
                       'duration_flow_down', 'changes_bulktrans_mode', 'duration_bulkmode',
                       'duration_bulkmode_up', 'duration_bulkmode_down', 'qouta_bulkmode',
                       'qouta_bulkmode_upstream', 'qouta_bulkmode_downstream',
                       'time_in_idle_mode', 'time_in_idle_mode_upstream', 'time_in_idle_mode_downstream',
                       'time_in_idle_mode_qouta', 'time_in_idle_mode_qouta_up',
                       'time_in_idle_mode_qouta_down']]
        # print(input_data)
        validation_size = 0.5  # Testavimo dydis
        seed = 50
        X_train, X_validation, Y_train, Y_validation = model_selection.train_test_split(input_data, output_data,
                                                                                        test_size=validation_size,
                                                                                        random_state=seed)
        scoring = 'accuracy'

        models = []
        models.append(('LR', LogisticRegression()))
        models.append(('LDA', LinearDiscriminantAnalysis()))
        models.append(('KNN', KNeighborsClassifier()))
        models.append(('CART', DecisionTreeClassifier()))
        models.append(('NB', GaussianNB()))
        models.append(('SVM', SVC()))
        models.append(('RFC', RandomForestClassifier()))

        input_trains, input_test, expected_output_train, expected_output_test = model_selection.train_test_split(
            input_data,
            output_data,
            test_size=0.50,
            random_state=42)
        rf = RandomForestClassifier(n_estimators=3)
        rf.fit(input_trains, expected_output_train)
        accuracy = rf.score(input_test, expected_output_test)
        print("Accuracy: {}".format(accuracy))
        pred = rf.predict(testav)
        print(pred)
        prd = RandomForestClassifier(n_estimators=10, random_state=123456)
        prd.fit(input_trains, expected_output_train)
        prdresults = prd.predict(testav)
        accuracy2 = prd.score(input_test, expected_output_test)
        print(accuracy2)
        print(prdresults)
        try:
            os.remove("resultsfile.txt")
        except:
            print("file not found")
        numpy.savetxt('resultsfile.txt', prdresults, fmt='%10.0f', delimiter='\t')

        file = open('resultsfile.txt', 'r')
        results = file.read()
        one = ""
        facebookcount = 0
        twittercount = 0
        youtubecount = 0
        for result in results:
            if (result.__contains__('5')):
                one += "Facebook "
                facebookcount += 1
            if (result.__contains__('3')):
                one += "Twitter "
                twittercount += 1
            if (result.__contains__('4')):
                one += "Youtube "
                youtubecount += 1
        highest = max(facebookcount, twittercount, youtubecount)
        if (highest == facebookcount):
            browsed = "Facebook"
        if (highest == twittercount):
            browsed = "Twitter"
        if (highest == youtubecount):
            browsed = "Youtube"

        def help():
            messagebox.askquestion('Help',
                                   'Just press button "button" and you will see where you were browsing that session :)')

        def sparameters():
            messagebox.showinfo('Full review', one)

        def letssee():
            labbel2 = tk.Label(window, text="You browsed in: ", font=(0, 10))
            labbel2.place(relx=.40, rely=.3)
            labbel3 = tk.Label(window, text=browsed, font=(0, 20))
            labbel3.place(relx=.36, rely=.4)
            parameters = tk.Button(window, text="Full review", command=sparameters)
            parameters.place(relx=.0, rely=.5)

        window = tk.Tk()
        window.title("Classifier")
        window.geometry('500x350')
        labbel = tk.Label(window, text="Want to find out where you browsed?", font=(0, 10))
        labbel.place(relx=.32, rely=.1)
        help = tk.Button(window, text="HELP", command=help, width=10)
        help.place(relx=.80, rely=.9)
        button1 = tk.Button(window, text="Let's see!", width=10, command=letssee)
        button1.place(relx=.45, rely=.2)
        window.mainloop()
