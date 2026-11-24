FROM ubuntu:24.04
RUN apt-get update && apt-get install -y build-essential cmake ninja-build git libssl-dev proverif
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /liboqs \
 && cd /liboqs && cmake -GNinja -B build -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
 && ninja -C build && ninja -C build install && ldconfig
WORKDIR /app
COPY . .
RUN make qrgaka
CMD ["sh", "-c", "make run && make proverif"]
