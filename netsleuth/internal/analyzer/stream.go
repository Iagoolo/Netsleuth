package analyzer

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

type httpStreamFactory struct{}

func (f *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {

	return &httpStream{
		net:       net,
		transport: transport,
	}
}

type httpStream struct {
	net, transport gopacket.Flow
	dados          bytes.Buffer
}

func (s *httpStream) Reassembled(reassembly []tcpassembly.Reassembly) {

	for _, pedaco := range reassembly {
		s.dados.Write(pedaco.Bytes)
	}
}

func (s *httpStream) ReassemblyComplete() {

	payloadCompleto := s.dados.Bytes()

	fmt.Printf("[+] Conexão TCP encerrada. Arquivo montado com %d bytes!\n", len(payloadCompleto))

	// Filtro de "Caçamba Vazia": Só imprime se houver dados (ignora o Handshake)
	if len(payloadCompleto) > 0 {
		fmt.Printf("Origem: %s:%s\n", s.net.Src().String(), s.transport.Src().String())
		fmt.Printf("Destino: %s:%s\n", s.net.Dst().String(), s.transport.Dst().String())

		if bytes.HasPrefix(payloadCompleto, []byte("HTTP/")) {
			fmt.Println("[!] ALERTA: Resposta do servidor interceptada")

			partes := bytes.SplitN(payloadCompleto, []byte("\r\n\r\n"), 2)

			if len(partes) == 2 {

				cabecalho := partes[0]
				arquivoBinario := partes[1]

				fmt.Printf("Cabeçalho identificado: \n%s\n", string(cabecalho))

				extensao := ".bin"

				if bytes.HasPrefix(arquivoBinario, []byte("GIF")) {
					extensao = ".gif"
				} else if bytes.HasPrefix(bytes.ToUpper(arquivoBinario), []byte("<HTML>")) {
					extensao = ".html"
				} else if bytes.HasPrefix(arquivoBinario, []byte{0xFF, 0xD8, 0xFF}) {
					extensao = ".jpg"
				} else if bytes.HasPrefix(arquivoBinario, []byte{0x00, 0x00, 0x01, 0x00}) {
					extensao = ".ico"
				} else {

					if len(arquivoBinario) >= 4 {
						fmt.Printf("[?] Arquivo binário começa com: % X\n", arquivoBinario[:4])
					}
				}

				timestamp := time.Now().UnixMilli()
				nomearquivo := fmt.Sprintf("evidencia_%s_%d%s", s.net.Dst().String(), timestamp, extensao)

				os.MkdirAll("evidencias", 0755)

				caminhoCompleto := filepath.Join("evidencias", nomearquivo)

				err := os.WriteFile(caminhoCompleto, arquivoBinario, 0644)

				if err != nil {
					fmt.Println("[*] Erro ao salvar o arquivo")
				} else {
					fmt.Printf("[+] Arquivo salvo com sucesso em %s\n", caminhoCompleto)
				}
			} else {
				fmt.Println("[*] ERRO! Pacote tcp fragmentado, não foi possível identificar cabeçalho e arquivo binário")
			}

		} else {
			fmt.Println("[*] Requisição do servidor interceptada")
		}
	}
}

func SetupAssembler() *tcpassembly.Assembler {
	fabrica := &httpStreamFactory{}
	piscina := tcpassembly.NewStreamPool(fabrica)
	gerente := tcpassembly.NewAssembler(piscina)

	return gerente
}
