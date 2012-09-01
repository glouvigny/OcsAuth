VERSION = 1.0.0

FLAGS = -linkpkg

SRC = oauth.ml oauth_endpoints.ml test_callbacks.ml oauth_api_tests.ml
SRCDOC = oauth.ml

CMO = $(SRC:.ml=.cmo)
CMI = $(SRC:.ml=.cmi)

PACKS = netstring,netclient,equeue-ssl,str,yojson
COMPILER = ocamlc
DOCCOMPILER = ocamldoc
OCAMLFIND = ocamlfind
NAME = test_lib
RM = rm -f

all:	
	$(OCAMLFIND) $(COMPILER) -o $(NAME) -package $(PACKS) $(SRC) $(FLAGS)

doc:
	$(OCAMLFIND) $(DOCCOMPILER) -html -package $(PACKS) $(SRCDOC)

clean:
	$(RM) $(CMI) $(CMO)

fclean: clean
	$(RM) $(NAME)

re: fclean all