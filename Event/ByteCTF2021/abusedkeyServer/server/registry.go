package server

import (
	"log"
)

func init() {
	log.Println("Setting EllipticCurve Default Options")
	ellipticCurveOption.CompleteEllipticCurveOption()
}
