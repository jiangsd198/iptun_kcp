all:
	go build .
install:
	mkdir -p $(DESTDIR)../../bin
	cp server $(DESTDIR)../../bin
	chmod 755 $(DESTDIR)../../bin/server
clean:  
	rm -f server
