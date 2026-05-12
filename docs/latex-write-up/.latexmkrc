# Put all build artifacts (.aux, .log, .pdf, etc.) into ./build/ instead of the
# source directory.
$out_dir = 'build';
$aux_dir = 'build';

# Engine + options.
$pdf_mode = 1;        # use pdflatex
$pdflatex = 'pdflatex -interaction=nonstopmode -halt-on-error -synctex=1 %O %S';

# How many runs to make. latexmk normally figures this out, but be explicit
# for predictability.
$max_repeat = 5;
