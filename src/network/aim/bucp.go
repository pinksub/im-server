package aim

import (
	"chimera/network"
	"chimera/utility/database"
	"chimera/utility/logging"
	"chimera/utility/configuration"
	"crypto/rand"
	"crypto/md5"
	"encoding/binary"
	"bytes"
)

const (
	SubgroupLoginRequest      = 0x0002
	SubgroupLoginResponse     = 0x0003
	SubgroupChallengeRequest  = 0x0006
	SubgroupChallengeResponse = 0x0007
)

func BUCPIncomingSNACData(client *network.Client, context *AIMContext, message *SNACMessage) {
	switch message.Subgroup {
	case SubgroupChallengeRequest:
		tlvs, err := TLVsDeserialize(message.Data)
		if err != nil {
			return
		}

		screenNameTlv := FindTLV(tlvs, 0x0001)
		if screenNameTlv == nil {
			return
		}

		client.ClientAccount.DisplayName = string(screenNameTlv.Value)

		context.Challenge = make([]byte, 56)
		_, err = rand.Read(context.Challenge)

		if err != nil {
			return
		}

		data := make([]byte, 2+len(context.Challenge))

		binary.BigEndian.PutUint16(data[0:2], uint16(len(context.Challenge)))
		copy(data[2:], context.Challenge)

		IncrementSequence(context)

		challengeSnac := NewSNAC(message.Foodgroup, SubgroupChallengeResponse, 0, 0, data)
		challengeFlap := NewFLAP(FrameData, context.ServerSequence, SNACDeserialize(challengeSnac))

		client.Connection.BinaryWriteTraffic(FLAPDeserialize(challengeFlap))

	case SubgroupLoginRequest:
		if context.Challenge == nil {
			return
		}

		tlvs, err := TLVsDeserialize(message.Data)
		if err != nil {
			return
		}

		passwordTlv := FindTLV(tlvs, 0x0025)
		if passwordTlv == nil {
			return
		}

		account, err := database.GetAccountDataByDisplayName(client.ClientAccount.DisplayName)

		if err != nil {
			logging.Error("AIM/BUCP", "Failed to fetch Account Data! (%s)", err.Error())
			return
		}

		salt := []byte("AOL Instant Messenger (SM)")

		hasher := md5.New()

		// get md5 hash of password
		hasher.Reset()
		hasher.Write([]byte(account.Password))
		md5Pass := hasher.Sum(nil)

		// generate older-style MD5 hash
		hasher.Reset()
		hasher.Write(context.Challenge)
		hasher.Write([]byte(account.Password))
		hasher.Write(salt)

		oldMD5Hash := hasher.Sum(nil)

		// generate new MD5 hash
		hasher.Reset()
		hasher.Write(context.Challenge)
		hasher.Write(md5Pass)
		hasher.Write(salt)

		newMD5Hash := hasher.Sum(nil)

		data := []byte{}
		conn := configuration.GetConfiguration().Connection

		if bytes.Equal(passwordTlv.Value, oldMD5Hash) || bytes.Equal(passwordTlv.Value, newMD5Hash) {
			context.Challenge = nil
			context.BOSCookie = make([]byte, 256)
			context.UIN		  = account.UIN

			_, err = rand.Read(context.BOSCookie)

			if err != nil {
				return
			}

			logging.Info("AIM/BUCP", "%s has signed in successfully.", account.DisplayName)

			screenNameTlv 	:= NewTLV(0x0001, []byte(account.DisplayName))
			bosAddrTlv 		:= NewTLV(0x0005, []byte(conn.Root + ":5191"))
			bosCookieTlv 	:= NewTLV(0x0006, context.BOSCookie)
			emailTlv 		:= NewTLV(0x0011, []byte(account.Mail))
			pwdChangeUrlTlv := NewTLV(0x0054, []byte("http://" + conn.Root + "/passport/forgot.php"))

			data = append(data, TLVDeserialize(screenNameTlv)...)
			data = append(data, TLVDeserialize(bosAddrTlv)...)
			data = append(data, TLVDeserialize(bosCookieTlv)...)
			data = append(data, TLVDeserialize(emailTlv)...)
			data = append(data, TLVDeserialize(pwdChangeUrlTlv)...)

			clientContexts = append(clientContexts, context)

		} else {
			logging.Info("AIM/BUCP", "Incorrect username or password?")

			screenNameTlv 	:= NewTLV(0x0001, []byte(account.DisplayName))
			errorCodeTlv    := NewTLV(0x0008, []byte{0x00, 0x05})
			errorUrlTlv     := NewTLV(0x0004, []byte("http://" + conn.Root + "/passport/forgot.php"))
			pwdChangeUrlTlv := NewTLV(0x0054, []byte("http://" + conn.Root + "/passport/forgot.php"))

			data = append(data, TLVDeserialize(screenNameTlv)...)
			data = append(data, TLVDeserialize(errorCodeTlv)...)
			data = append(data, TLVDeserialize(errorUrlTlv)...)
			data = append(data, TLVDeserialize(pwdChangeUrlTlv)...)
		}

		IncrementSequence(context)

		snac := NewSNAC(message.Foodgroup, SubgroupLoginResponse, 0, 0, data)
		flap := NewFLAP(FrameData, context.ServerSequence, SNACDeserialize(snac))
		client.Connection.BinaryWriteTraffic(FLAPDeserialize(flap))
	}
}
