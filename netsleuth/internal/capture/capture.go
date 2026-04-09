package capture

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Config struct{
	SnapLen int32
	Promiscuous bool
	Timeout time.Duration
	Device string
}

func Start(c Config, bpfFilter string) (*pcap.Handle, *gopacket.PacketSource, error){

	handle, err := pcap.OpenLive(c.Device, c.SnapLen, c.Promiscuous, c.Timeout)

	if err != nil{
		return nil, nil, err
	}

	if bpfFilter != ""{
		err = handle.SetBPFFilter(bpfFilter)

		if err != nil{
			handle.Close()
			return nil, nil, err
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	return handle, packetSource, nil
}