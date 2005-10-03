all: manual

# Run pdflatex twice to get the references right:
manual: PTLsimManual.lyx
	lyx PTLsimManual.lyx --export text
	lyx PTLsimManual.lyx --export latex
	pdflatex PTLsimManual.tex
	pdflatex PTLsimManual.tex
	mkdir html; latex2html PTLsimManual.tex -split 3 -noinfo -local_icons -dir html
