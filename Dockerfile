# Clear cache: 
# docker builder prune

# Build: 
# DOCKER_BUILDKIT=1 docker build -o output .
# for Windows, use 
# { "features": { "buildkit": true } }
# instead of the environment variable

# Build a container
#FROM debian:bullseye as main_bullseye
#ENV DEBIAN_FRONTEND="noninteractive" TZ="Europe/London"
#RUN apt-get update -y && apt-get install -y \ 
#    git && apt-get install -y --no-install-recommends make g++ pkg-config qtbase5-dev libssl-dev libzip-dev
#
#FROM debian:buster as main_buster
#ENV DEBIAN_FRONTEND="noninteractive" TZ="Europe/London"
#RUN apt-get update -y && apt-get install -y \ 
#    git && apt-get install -y --no-install-recommends make g++ pkg-config qtbase5-dev libssl-dev libzip-dev

FROM debian:stretch as main_stretch
ENV DEBIAN_FRONTEND="noninteractive" TZ="Europe/London"
RUN apt-get update -y && apt-get install -y \ 
    git && apt-get install -y --no-install-recommends make g++ pkg-config qtbase5-dev libssl-dev libzip-dev




#FROM main_bullseye as compile_bullseye
#RUN git clone git://soutade.fr/libgourou.git && \
#    cd libgourou && \
#    make BUILD_SHARED=1 BUILD_UTILS=1
#    mkdir final && \
#    cp utils/acsmdownloader final/ && \
#    cp utils/adept_activate final/ && \
#    cp libgourou.so final/ && \
#    cp /usr/lib/x86_64-linux-gnu/libzip.so.4 final/ && \
#    true
#
#FROM main_buster as compile_buster
#RUN git clone git://soutade.fr/libgourou.git && \
#    cd libgourou && \
#    make BUILD_SHARED=1 BUILD_UTILS=1
#    mkdir final && \
#    cp utils/acsmdownloader final/ && \
#    cp utils/adept_activate final/ && \
#    cp libgourou.so final/ && \
#    cp /usr/lib/x86_64-linux-gnu/libzip.so.4 final/ && \
#    true

FROM main_stretch as compile_stretch
RUN git clone git://soutade.fr/libgourou.git && \
    cd libgourou && \
    make BUILD_SHARED=1 BUILD_UTILS=1 && \
    mkdir final && \
    cp utils/acsmdownloader final/ && \
    cp utils/adept_activate final/ && \
    cp libgourou.so final/ && \
    cp /usr/lib/x86_64-linux-gnu/libzip.so.4 final/ && \
    true


FROM scratch AS export-stage
#COPY --from=compile_bullseye /libgourou/final/  /bullseye/
#COPY --from=compile_buster /libgourou/final/  /buster/
COPY --from=compile_stretch /libgourou/final/  /stretch/

