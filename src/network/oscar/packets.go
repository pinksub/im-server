package oscar

import (
	"bytes"
	"chimera/network"
	"chimera/utility/configuration"
	"chimera/utility/database"
	"chimera/utility/logging"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

/* == Handlers == */

func OSCARHandleAuthenticationFrameDataFromFLAP(client *network.Client, context *OSCARContext, flap *FLAPPacket) {
	switch flap.Frame {
	case FrameSignOn:
		OSCARHandleClientFLAPSignOnFrame(client, context, flap)
	case FrameData:
		snac := OSCARSerializeSNAC(flap.Data)

		switch snac.Foodgroup {
		case FoodgroupBUCP:

			switch snac.Subgroup {
			case BUCPChallengeRequest:
				OSCARHandleClientBUCPChallengeRequest(client, context, snac)
			case BUCPLoginRequest:
				OSCARHandleClientBUCPLoginRequest(client, context, snac)
			}

		}
	}
}

func OSCARHandleBOSFrameDataFromFLAP(client *network.Client, context *OSCARContext, flap *FLAPPacket) {
	switch flap.Frame {
	case FrameSignOn:
		OSCARHandleClientBOSFrameSignOn(client, context, flap)
	case FrameData:
		//snac := SNACSerialize(packet.Data)

	}
}

/* == FLAP == */

func OSCARHandleClientFLAPSignOnFrame(client *network.Client, context *OSCARContext, flap *FLAPPacket) {
	// thanks iserverd docs and src <3
	icqxor := []byte{
		0xF3, 0x26, 0x81, 0xC4, 0x39, 0x86, 0xDB, 0x92,
		0x71, 0xA3, 0xB9, 0xE6, 0x53, 0x7A, 0x95, 0x7C,
	}
	/*
		0xF3 0x26 0x81 0xC4 0x39 0x86 0xDB 0x92
		\x71\xA3\xB9\xE6\x53\x7A\x95\x7C'

	*/

	tlvs, err := OSCARDeserializeMultipleTLVs(flap.Data[4:])

	if err != nil {
		logging.Error("OSCAR/FLAP Authentication", "Failed to Deserialize TLVs from FLAP Data (%s)", err.Error())
		return
	}

	screenNameTlv := OSCARFindTLV(tlvs, 0x0001)
	if screenNameTlv == nil {
		logging.Error("OSCAR/FLAP Authentication", "Failed to find ScreenName TLV")
		return
	}

	roastedtlv := OSCARFindTLV(tlvs, 0x0002)
	if roastedtlv == nil {
		logging.Error("OSCAR/FLAP Authentication", "Failed to find Roasted Password TLV")
		return
	}

	roast := roastedtlv.Value
	ret := make([]byte, len(roastedtlv.Value))
	kx := 0
	for ix := 0; ix < len(roast); ix++ {
		if kx > 16 {
			kx = 0
		}

		ret[ix] = roast[ix] ^ icqxor[kx]
		kx++
	}

	logging.Debug("OSCAR/FLAP Authentication", "Roasted PW: %v", roast)
	logging.Debug("OSCAR/FLAP Authentication", "Unroasted PW: %v", ret)

	client.ClientAccount, err = database.GetAccountDataByDisplayName(string(screenNameTlv.Value))

	if err != nil {
		logging.Error("OSCAR/FLAP Authentication", "Failed to fetch Account Data! (%s)", err.Error())
		return
	}

	logging.Debug("OSCAR/FLAP Authentication", "NetworkAccount UIN: %d", client.ClientAccount.UIN)
	logging.Debug("OSCAR/FLAP Authentication", "NetworkAccount SN: %s", client.ClientAccount.DisplayName)
	logging.Debug("OSCAR/FLAP Authentication", "NetworkAccount Mail: %s", client.ClientAccount.Mail)
	logging.Debug("OSCAR/FLAP Authentication", "NetworkAccount PW: %v", []byte(client.ClientAccount.Password))

	data := []byte{}
	if bytes.Equal(ret, []byte(client.ClientAccount.Password)) {
		context.BOSCookie = make([]byte, 256)
		_, err = rand.Read(context.BOSCookie)

		if err != nil {
			logging.Error("OSCAR/FLAP Authentication", "Failed to generate BOS Cookie! (%s)", err.Error())
			return
		}

		clientversion := OSCARFindTLV(tlvs, 0x0003)
		logging.Info("OSCAR", "Client successfully authenticated! (UIN: %d, SN: %s, Version: %s, Proto: OSCAR)", client.ClientAccount.UIN, client.ClientAccount.DisplayName, clientversion.Value)

		screenNameTlv := OSCARNewTLV(0x0001, []byte(client.ClientAccount.DisplayName))
		bosAddrTlv := OSCARNewTLV(0x0005, []byte(configuration.GetConfiguration().Connection.Root+":5191"))
		bosCookieTlv := OSCARNewTLV(0x0006, context.BOSCookie)

		data = append(data, OSCARDeserializeTLV(screenNameTlv)...)
		data = append(data, OSCARDeserializeTLV(bosAddrTlv)...)
		data = append(data, OSCARDeserializeTLV(bosCookieTlv)...)
	} else {
		logging.Warn("OSCAR", "Client has failed FLAP authentication! (UIN: %d, SN: %s)", client.ClientAccount.UIN, string(screenNameTlv.Value))

		screenNameTlv := OSCARNewTLV(0x0001, []byte(client.ClientAccount.DisplayName))
		errorCodeTlv := OSCARNewTLV(0x0008, []byte{0x00, 0x04})
		errorUrlTlv := OSCARNewTLV(0x0004, []byte(fmt.Sprintf("http://%s/", configuration.GetConfiguration().Connection.Root)))
		unkTlv := OSCARNewTLV(0x000C, []byte{0x00, 0x00})

		data = append(data, OSCARDeserializeTLV(screenNameTlv)...)
		data = append(data, OSCARDeserializeTLV(errorCodeTlv)...)
		data = append(data, OSCARDeserializeTLV(errorUrlTlv)...)
		data = append(data, OSCARDeserializeTLV(unkTlv)...)
	}

	OSCARIncrementServerSequence(context)

	flappack := OSCARNewFLAPPacket(FrameSignOff, context.ServerSequence, data)
	client.Connection.BinaryWriteTraffic(OSCARDeserializeFLAP(flappack))
}

/* == BUCP == */

func OSCARHandleClientBUCPChallengeRequest(client *network.Client, context *OSCARContext, message *SNACMessage) {
	context.Challenge = make([]byte, 56)
	_, err := rand.Read(context.Challenge)

	if err != nil {
		logging.Error("OSCAR/BUCP Authentication", "Failed to generate Challenge! (%s)", err.Error())
		return
	}

	data := make([]byte, 2+len(context.Challenge))

	binary.BigEndian.PutUint16(data[0:2], uint16(len(context.Challenge)))
	copy(data[2:], context.Challenge)

	OSCARIncrementServerSequence(context)

	challengeSnac := OSCARNewSNAC(message.Foodgroup, BUCPChallengeResponse, 0, 0, data)
	challengeFlap := OSCARNewFLAPPacket(FrameData, context.ServerSequence, OSCARDeserializeSNAC(challengeSnac))

	client.Connection.BinaryWriteTraffic(OSCARDeserializeFLAP(challengeFlap))
}

func OSCARHandleClientBUCPLoginRequest(client *network.Client, context *OSCARContext, message *SNACMessage) {
	if context.Challenge == nil {
		logging.Error("OSCAR/BUCP Authentication", "No BUCP Challenge Provided")
		return
	}

	tlvs, err := OSCARDeserializeMultipleTLVs(message.Data)
	if err != nil {
		logging.Error("OSCAR/BUCP Authentication", "Failed to Deserialize TLVs from SNAC Data")
		return
	}

	passwordTlv := OSCARFindTLV(tlvs, 0x0025)
	if passwordTlv == nil {
		logging.Error("OSCAR/BUCP Authentication", "Failed to find Password TLV")
		return
	}

	screenNameTlv := OSCARFindTLV(tlvs, 0x0001)
	if screenNameTlv == nil {
		logging.Error("OSCAR/BUCP Authentication", "Failed to find ScreenName TLV")
		return
	}

	client.ClientAccount, err = database.GetAccountDataByDisplayName(string(screenNameTlv.Value))

	if err != nil {
		logging.Error("OSCAR/BUCP Authentication", "Failed to fetch Account Data! (%s)", err.Error())
		return
	}

	logging.Debug("OSCAR/BUCP Authentication", "NetworkAccount UIN: %d", client.ClientAccount.UIN)
	logging.Debug("OSCAR/BUCP Authentication", "NetworkAccount SN: %s", client.ClientAccount.DisplayName)
	logging.Debug("OSCAR/BUCP Authentication", "NetworkAccount Mail: %s", client.ClientAccount.Mail)
	logging.Debug("OSCAR/BUCP Authentication", "NetworkAccount PW: %v", []byte(client.ClientAccount.Password))

	client.ClientUser, err = database.GetUserDetailsDataByUIN(client.ClientAccount.UIN)

	logging.Debug("OSCAR/BUCP Authentication", "NetworkUser UIN: %d", client.ClientUser.UIN)
	logging.Debug("OSCAR/BUCP Authentication", "NetworkUser SignupDate: %d", client.ClientUser.SignupDate)

	if err != nil {
		logging.Error("OSCAR/BUCP Authentication", "Failed to fetch UserDetails Data! (%s)", err.Error())
		return
	}

	salt := []byte("AOL Instant Messenger (SM)")

	hasher := md5.New()

	// get md5 hash of password
	hasher.Reset()
	hasher.Write([]byte(client.ClientAccount.Password))
	md5Pass := hasher.Sum(nil)

	// generate older-style MD5 hash
	hasher.Reset()
	hasher.Write(context.Challenge)
	hasher.Write([]byte(client.ClientAccount.Password))
	hasher.Write(salt)

	oldMD5Hash := hasher.Sum(nil)

	// generate new MD5 hash
	hasher.Reset()
	hasher.Write(context.Challenge)
	hasher.Write(md5Pass)
	hasher.Write(salt)

	newMD5Hash := hasher.Sum(nil)

	logging.Debug("OSCAR/BUCP Authentication", "TLV PW: %v", passwordTlv.Value)
	logging.Debug("OSCAR/BUCP Authentication", "MD5 PW: %v", md5Pass)
	logging.Debug("OSCAR/BUCP Authentication", "OldStyle MD5 PW: %v", oldMD5Hash)
	logging.Debug("OSCAR/BUCP Authentication", "NewStyle MD5 PW: %v", newMD5Hash)

	data := []byte{}
	conn := configuration.GetConfiguration().Connection

	if bytes.Equal(passwordTlv.Value, oldMD5Hash) || bytes.Equal(passwordTlv.Value, newMD5Hash) {
		context.Challenge = nil
		context.BOSCookie = make([]byte, 256)

		_, err = rand.Read(context.BOSCookie)

		if err != nil {
			logging.Error("OSCAR/BUCP Authentication", "Failed to generate BOS Cookie! (%s)", err.Error())
			return
		}

		clientversion := OSCARFindTLV(tlvs, 0x0003)

		//	logging.Info("MySpace", "Client successfully authenticated! (UIN: %d, SN: %s, Mail: %s, Build: %s, Proto: %s)", cli.ClientAccount.UIN, cli.ClientAccount.DisplayName, cli.ClientAccount.Mail, cli.ClientInfo.Build, cli.ClientInfo.Protocol)
		// i've left out Build from the message since idk how or even if BUCP even knows what version is being used - Lu
		// nvm that last comment, figured out that 0x0003 contains the clients version string, we now also print the clientversion on successful login - Lu
		logging.Info("OSCAR", "Client successfully authenticated! (UIN: %d, SN: %s, Version: %s, Proto: OSCAR)", client.ClientAccount.UIN, client.ClientAccount.DisplayName, clientversion.Value)

		screenNameTlv := OSCARNewTLV(0x0001, []byte(client.ClientAccount.DisplayName))
		bosAddrTlv := OSCARNewTLV(0x0005, []byte(conn.Root+":5191"))
		bosCookieTlv := OSCARNewTLV(0x0006, context.BOSCookie)
		emailTlv := OSCARNewTLV(0x0011, []byte(client.ClientAccount.Mail))
		pwdChangeUrlTlv := OSCARNewTLV(0x0054, []byte(fmt.Sprintf("http://%s/passport/forgot.php", conn.Root))) //http://"+conn.Root+"/passport/forgot.php

		data = append(data, OSCARDeserializeTLV(screenNameTlv)...)
		data = append(data, OSCARDeserializeTLV(bosAddrTlv)...)
		data = append(data, OSCARDeserializeTLV(bosCookieTlv)...)
		data = append(data, OSCARDeserializeTLV(emailTlv)...)
		data = append(data, OSCARDeserializeTLV(pwdChangeUrlTlv)...)

		clientContexts = append(clientContexts, context)

	} else {
		// i fall back on SNTLV here since client.ClientAccount.DisplayName could be empty if the fetch failed (i.e wrong username)
		logging.Warn("OSCAR", "Client has failed BUCP authentication! (UIN: %d, SN: %s)", client.ClientAccount.UIN, string(screenNameTlv.Value))

		screenNameTlv := OSCARNewTLV(0x0001, []byte(client.ClientAccount.DisplayName))
		errorCodeTlv := OSCARNewTLV(0x0008, []byte{0x00, 0x04})
		errorUrlTlv := OSCARNewTLV(0x0004, []byte(fmt.Sprintf("http://%s/", conn.Root)))
		pwdChangeUrlTlv := OSCARNewTLV(0x0054, []byte(fmt.Sprintf("http://%s/passport/forgot.php", conn.Root)))

		data = append(data, OSCARDeserializeTLV(screenNameTlv)...)
		data = append(data, OSCARDeserializeTLV(errorCodeTlv)...)
		data = append(data, OSCARDeserializeTLV(errorUrlTlv)...)
		data = append(data, OSCARDeserializeTLV(pwdChangeUrlTlv)...)
	}

	OSCARIncrementServerSequence(context)

	snac := OSCARNewSNAC(message.Foodgroup, BUCPLoginResponse, 0, 0, data)
	flap := OSCARNewFLAPPacket(FrameData, context.ServerSequence, OSCARDeserializeSNAC(snac))
	client.Connection.BinaryWriteTraffic(OSCARDeserializeFLAP(flap))
}

/* == BOS == */

func OSCARHandleClientBOSFrameSignOn(client *network.Client, context *OSCARContext, flap *FLAPPacket) {
	tlvs, err := OSCARDeserializeMultipleTLVs(flap.Data[4:])
	if err != nil {
		return
	}

	cookieTlv := OSCARFindTLV(tlvs, 0x0006)
	if cookieTlv == nil {
		return
	}

	for _, clientContext := range clientContexts {
		if bytes.Equal(clientContext.BOSCookie, cookieTlv.Value) {
			logging.Debug("OSCAR/BOS Frame SignOn", "Matching cookie attempt found")
			clientContext.ServerSequence = context.ServerSequence
			context = clientContext

			logging.Debug("OSCAR/BOS Frame SignOn", "Sending supported services")

			foodgroups := make([]byte, 0)
			for _, supportedFoodgroup := range supportedFoodgroups {
				binary.BigEndian.AppendUint16(foodgroups, supportedFoodgroup)
			}

			OSCARIncrementServerSequence(context)

			snac := OSCARNewSNAC(FoodgroupOSERVICE, OSERVICEHostOnline, 0, 0, foodgroups)
			flap = OSCARNewFLAPPacket(FrameData, context.ServerSequence, OSCARDeserializeSNAC(snac))
			client.Connection.BinaryWriteTraffic(OSCARDeserializeFLAP(flap))
		}
	}

	logging.Debug("OSCAR/BOS Frame SignOn", "No matching cookie attempt?")
}
