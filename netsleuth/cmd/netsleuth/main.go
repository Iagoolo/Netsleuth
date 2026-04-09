package main

import (
	"fmt"
	"log"
	"time"

	"netsleuth/internal/capture"
	"netsleuth/internal/analyzer"
)

func main(){

	config  := capture.Config{
		SnapLen: 65535,
		Promiscuous: true,
		Timeout: 30 * time.Second,
		Device: "wlp1s0",
	}

	filtro := "tcp and port 80"

	fmt.Printf("[*] Iniciando o Netsleuth na interface %s...\n", config.Device)
	fmt.Printf("[*] Filtro BPF aplicado: %s\n", filtro)
	fmt.Printf("[*] Escutando o tráfego... (Pressione CTRL+C para parar)\n\n")

	handle, packetSource, err := capture.Start(config, filtro)

	if err != nil{
		log.Fatalf("[!] Falha fatal ao abrir a placa de rede: %v\n", err)
	}

	defer handle.Close()

	for packet := range packetSource.Packets(){
		analyzer.ProcessPacket(packet)
	}
}