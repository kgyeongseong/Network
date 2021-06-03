all: pcap_capture_first

pcap_capture_first:
	gcc -o pcap_capture_first pcap_capture_first.c -lpcap

clean:
	rm -f pcap_capture_first *.o *.c
