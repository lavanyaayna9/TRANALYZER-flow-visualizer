PDOC3 := pdoc3
DEST  := t2pydoc

.PHONY: all clean doc

all: doc

doc:
	$(PDOC3) --html --force --filter T2,__init__.py --output-dir $(DEST) .
	mv $(DEST)/t2py/* $(DEST)/
	rmdir $(DEST)/t2py

clean:
	rm -rf $(DEST)

.PHONY: lama

lama:
	pylama -i E501,E265

.PHONY: test_t2utils test_t2plugin test_t2 test

test_t2utils:
	./tests/test_t2py.py -u

test_t2plugin:
	./tests/test_t2py.py -p

test_t2:
	./tests/test_t2py.py -t

test:
	./tests/test_t2py.py

.PHONY: coverage

coverage:
	coverage run tests/test_t2py.py
	coverage report -m T2*.py | column -t -s$$'\t' | less -S
	coverage report -m T2*.py | gawk '/^T2/ { print $$1 ": " $$4}'
