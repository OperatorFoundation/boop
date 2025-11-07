package main

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/faiface/beep"
	"github.com/faiface/beep/speaker"
	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
)

var (
	speakerInitialized bool
	speakerMutex       sync.Mutex
)

func playBoopSound() {
	// Initialize speaker once
	speakerMutex.Lock()
	if !speakerInitialized {
		sr := beep.SampleRate(44100)
		speaker.Init(sr, sr.N(time.Millisecond*100))
		speakerInitialized = true
	}
	speakerMutex.Unlock()

	// Load config
	config := loadConfig()

	// Generate the boop sound using bytebeat
	sr := beep.SampleRate(8000) // Bytebeat typically sounds good at 8kHz
	duration := sr.N(time.Millisecond * time.Duration(config.Duration))

	// Create bytebeat streamer
	bytebeatStreamer := &BytebeatStreamer{
		SampleRate: sr,
		Expression: config.Bytebeat,
		Duration:   duration,
		Position:   0,
	}

	// Apply volume control
	volume := &VolumeControl{
		Streamer: beep.Resample(4, sr, beep.SampleRate(44100), bytebeatStreamer),
		Volume:   config.Volume,
	}

	speaker.Play(volume)
}

// BytebeatStreamer generates audio from a bytebeat expression
type BytebeatStreamer struct {
	SampleRate beep.SampleRate
	Expression string
	Duration   int
	Position   int
	fn         func(int) int
	initOnce   sync.Once
}

func (b *BytebeatStreamer) initFunction() {
	// Use yaegi to interpret the bytebeat expression
	i := interp.New(interp.Options{})
	i.Use(stdlib.Symbols)

	// Create a function that evaluates the expression
	code := fmt.Sprintf(`
package main

import "math"

func bytebeat(t int) int {
	return %s
}
`, b.Expression)

	_, err := i.Eval(code)
	if err != nil {
		// Fallback to simple sine wave if expression fails
		b.fn = func(t int) int {
			return int(127 * math.Sin(float64(t)*0.1))
		}
		return
	}

	// Get the function
	fn, err := i.Eval("main.bytebeat")
	if err != nil {
		b.fn = func(t int) int {
			return int(127 * math.Sin(float64(t)*0.1))
		}
		return
	}

	// Wrap it
	b.fn = func(t int) int {
		result := fn.Interface().(func(int) int)(t)
		return result & 0xFF // Keep in byte range
	}
}

func (b *BytebeatStreamer) Stream(samples [][2]float64) (n int, ok bool) {
	b.initOnce.Do(b.initFunction)

	for i := range samples {
		if b.Position >= b.Duration {
			return i, false
		}

		// Generate bytebeat sample
		byteSample := b.fn(b.Position)

		// Convert from 0-255 to -1.0 to 1.0
		sample := (float64(byteSample) - 128.0) / 128.0

		samples[i][0] = sample
		samples[i][1] = sample
		b.Position++
		n++
	}
	return n, true
}

func (b *BytebeatStreamer) Err() error {
	return nil
}

// VolumeControl applies volume control to the audio
type VolumeControl struct {
	Streamer beep.Streamer
	Volume   float64
}

func (v *VolumeControl) Stream(samples [][2]float64) (n int, ok bool) {
	n, ok = v.Streamer.Stream(samples)
	for i := 0; i < n; i++ {
		samples[i][0] *= v.Volume
		samples[i][1] *= v.Volume
	}
	return n, ok
}

func (v *VolumeControl) Err() error {
	return v.Streamer.Err()
}
