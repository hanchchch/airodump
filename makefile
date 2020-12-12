LDLIBS=-lpcap

all: airodump

airodump: main.o header/scheme/ip.o header/scheme/mac.o header/radiotaphdr.o header/beacon.o header/wirelessmanagement.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o header/*.o header/scheme/*.o