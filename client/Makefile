all:
	go build .
install:
	mkdir -p $(DESTDIR)../../bin
	cp client $(DESTDIR)../../bin
	chmod 755 $(DESTDIR)../../bin/client
clean:  
	rm -f client
