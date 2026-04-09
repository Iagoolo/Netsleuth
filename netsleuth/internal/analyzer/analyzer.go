package analyzer

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func ProcessPacket(packet gopacket.Packet) {

	ipLayer := packet.Layer(layers.LayerTypeIPv4)

	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			// Filtro de "Caçamba Vazia": Só imprime se houver dados (ignora o Handshake)
			if len(tcp.Payload) > 0 {
				fmt.Printf("Origem: %s:%d\n", ip.SrcIP, tcp.SrcPort)
				fmt.Printf("Destino: %s:%d\n", ip.DstIP, tcp.DstPort)

				if bytes.HasPrefix(tcp.Payload, []byte("HTTP/")) {
					fmt.Println("[!] ALERTA: Resposta do servidor interceptada")

					partes := bytes.SplitN(tcp.Payload, []byte("\r\n\r\n"), 2)

					if len(partes) == 2 {

						cabecalho := partes[0]
						arquivoBinario := partes[1]

						fmt.Printf("Cabeçalho identificado: \n%s\n", string(cabecalho))

						extensao := ".bin"

						if bytes.HasPrefix(arquivoBinario, []byte("GIF")){
							extensao = ".gif"
						} else if bytes.HasPrefix(bytes.ToUpper(arquivoBinario), []byte("<HTML>")){
							extensao = ".html"
						} else if bytes.HasPrefix(arquivoBinario, []byte{0xFF, 0xD8, 0xFF}){
							extensao = ".jpg"
						} else if bytes.HasPrefix(arquivoBinario, []byte{0x00, 0x00, 0x01, 0x00}) {
							extensao = ".ico"
						} else{

							if len(arquivoBinario) >= 4 {
								fmt.Printf("[?] Arquivo binário começa com: % X\n", arquivoBinario[:4])
							}
						}

						timestamp := time.Now().UnixMilli()

						nomearquivo := fmt.Sprintf("evidencia_%s_%d%s", ip.SrcIP, timestamp, extensao)

						err := os.WriteFile(nomearquivo, arquivoBinario, 0644)

						if err != nil {
							fmt.Println("[*] Erro ao salvar o arquivo")
						} else {
							fmt.Println("[+] Arquivo salvo com sucesso")
						}
					} else {
						fmt.Println("[*] ERRO! Pacote tcp fragmentado, não foi possível identificar cabeçalho e arquivo binário")
					}

				} else {
					fmt.Println("[*] Requisição do servidor interceptada")
				}

			}

		}
	}

}