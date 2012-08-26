VERSION = 1.0.0

FLAGS = -linkpkg

SRC = oauth.ml oauth_test.ml
CMO = $(SRC:.ml=.cmo)
CMI = $(SRC:.ml=.cmi)

PACKS = netstring,netclient,equeue-ssl
COMPILER = ocamlc
OCAMLFIND = ocamlfind
NAME = test_lib
RM = rm -f

all:	
	$(OCAMLFIND) $(COMPILER) -o $(NAME) -package $(PACKS) $(SRC) $(FLAGS)

clean:
	$(RM) $(CMI) $(CMO)

fclean: clean
	$(RM) $(NAME)

re: fclean all