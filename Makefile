#/**
#	Sisteme de programe pentru retele de calculatoare
#
#	Copyright (C) 2008 Ciprian Dobre & Florin Pop
#	Univerity Politehnica of Bucharest, Romania
#
#	This program is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.

#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
# */

build:
	rpcgen -C schema.x
	rpcgen -C -c schema.x > schema_xdr.c
	rpcgen -C -m schema.x > schema_svc.c
	rpcgen -C -l schema.x > schema_clnt.c
	g++ -o server main_svr.cc schema_svc.c schema_xdr.c -lnsl -Wall
	g++ -o client main_clt.cc schema_clnt.c schema_xdr.c -lnsl -Wall

clean:
	rm -f client server
