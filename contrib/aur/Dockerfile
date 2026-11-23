FROM archlinux:latest

RUN pacman -Syu --noconfirm git base-devel rust sudo && \
    useradd -m builder && \
    echo "builder ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

USER builder
WORKDIR /home/builder
