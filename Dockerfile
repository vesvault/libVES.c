FROM openquantumsafe/python:b0efd3b

FROM gcc

COPY --from=0 /usr/local/lib64/liboqs* /usr/local/lib64/
COPY --from=0 /usr/local/include/oqs /usr/local/include/oqs
COPY --from=0 /lib/*musl* /lib/

RUN ln -s /usr/local/lib64/liboqs* /usr/lib/

WORKDIR /usr/src/libVES.c
ADD . .
RUN ./configure --with-oqs || cat config.log
RUN make
RUN make install
RUN make clean
