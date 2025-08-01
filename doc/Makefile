PDFLATEX := $(shell which pdflatex)
RM       := /bin/rm -f

INFILE   := documentation

INPUT    := $(INFILE).tex
OUTPUT   := $(INFILE).pdf faq.pdf
TEMP     := $(wildcard *.aux *.log *.out *.svn *.toc *~)

.PHONY: all documentation faq

all: documentation faq

documentation: plugins_list.tex documentation_wo_plugins_list

documentation_wo_plugins_list: test_for_pdflatex
ifeq ($(wildcard $(INFILE).toc),)
	$(PDFLATEX) $(INPUT)
endif
	$(PDFLATEX) $(INPUT)
	$(PDFLATEX) $(INPUT)

faq: test_for_pdflatex
ifeq ($(wildcard faq.toc),)
	$(PDFLATEX) faq
endif
	$(PDFLATEX) faq
	$(PDFLATEX) faq

plugins_list.tex: clean_plugins_list_tex
	for p in $$(grep "\\\\documentclass\[documentation\]{subfiles}" ../plugins/*/doc/*.tex | cut -d: -f1 | grep -v t2PSkel); do \
		echo "\_ransubfile{$$p}" | sed 's/_/t/' >> plugins_list.tex; \
	done

.PHONY: test_for_pdflatex

test_for_pdflatex:
ifeq ($(PDFLATEX),)
	$(error "No pdflatex in $(PATH)")
endif

.PHONY: clean clean_plugins_list_tex clean_tutorials

clean: clean_plugins_list_tex clean_tutorials
ifneq ($(TEMP),)
	$(RM) $(TEMP)
endif

clean_plugins_list_tex:
	$(RM) "plugins_list.tex"

clean_tutorials:
	make -C tutorials clean

.PHONY: mrproper mrproper_tutorials

mrproper: clean mrproper_tutorials
	$(RM) $(OUTPUT)

mrproper_tutorials:
	make -C tutorials mrproper

.PHONY: distclean distclean_tutorials

distclean: mrproper distclean_tutorials

distclean_tutorials:
	make -C tutorials distclean
