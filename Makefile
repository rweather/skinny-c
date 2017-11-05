
.PHONY: all clean check

all:
	(cd src; $(MAKE) all)
	(cd test; $(MAKE) all)
	(cd examples; $(MAKE) all)

clean:
	(cd src; $(MAKE) clean)
	(cd test; $(MAKE) clean)
	(cd examples; $(MAKE) clean)

check:
	(cd src; $(MAKE) check)
	(cd test; $(MAKE) check)
	(cd examples; $(MAKE) check)
