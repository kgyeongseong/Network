all: pcap_capture_3

pcap_capture_3:
	gcc -o pcap_capture_3 pcap_capture_3.c -lpcap

clean:
	rm -f pcap_capture_3 *.o *.c
