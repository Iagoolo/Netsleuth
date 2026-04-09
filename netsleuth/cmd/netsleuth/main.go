package main

import (
	"fmt"
	"log"
	"time"
	"flag"

	"netsleuth/internal/capture"
	"netsleuth/internal/analyzer"
)

func main(){

	var interfaceRede string
	var filterBPF string

	flag.StringVar(&interfaceRede, "i", "wlp1s0", "Interface de rede para capturar os pacotes (ex: eth0, wlp1s0)")
	flag.StringVar(&filterBPF, "f", "tcp and port 80", "Filtro BPF de captura (ex: tcp and port 80)")

	flag.Parse()

	config  := capture.Config{
		SnapLen: 65535,
		Promiscuous: true,
		Timeout: 30 * time.Second,
		Device: interfaceRede,
	}

	fmt.Printf("[*] Iniciando o Netsleuth na interface %s...\n", config.Device)
	fmt.Printf("[*] Filtro BPF aplicado: %s\n", filterBPF)
	fmt.Printf("[*] Escutando o tráfego... (Pressione CTRL+C para parar)\n\n")

	handle, packetSource, err := capture.Start(config, filterBPF)

	if err != nil{
		log.Fatalf("[!] Falha fatal ao abrir a placa de rede: %v\n", err)
	}

	defer handle.Close()

	assembler := analyzer.SetupAssembler()

	defer assembler.FlushAll()

	lastFlush := time.Now()

	for packet := range packetSource.Packets(){
		analyzer.ProcessPacket(packet, assembler)

		if time.Since(lastFlush) > 2*time.Minute {
        	assembler.FlushOlderThan(time.Now().Add(-time.Minute))
        	lastFlush = time.Now()

			fmt.Println("[*] Faxina realizada: conexões inativas foram encerradas.")
        }
	}
}