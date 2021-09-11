package main

import (
	"testing"

	"github.com/briandemant/go-password-cracker/cracker"
)

func TestHash_superman(t *testing.T) {
	actual := cracker.CrackSHA1Hash("18c28604dd31094a8d69dae60f1bcd347f1afc5a", false)
	if actual == "superman" {
		t.Logf("success: expected '%v', got '%v'", "superman", actual)
	} else {
		t.Errorf("failed: expected '%v', got '%v'", "superman", actual)
	}
}

func TestHash_q1w2e3r4t5(t *testing.T) {
	actual := cracker.CrackSHA1Hash("5d70c3d101efd9cc0a69f4df2ddf33b21e641f6a", false)
	if actual == "q1w2e3r4t5" {
		t.Logf("success: expected '%v', got '%v'", "q1w2e3r4t5", actual)
	} else {
		t.Errorf("failed: expected '%v', got '%v'", "q1w2e3r4t5", actual)
	}
}

func TestHash_bubbles1(t *testing.T) {
	actual := cracker.CrackSHA1Hash("b80abc2feeb1e37c66477b0824ac046f9e2e84a0", false)
	if actual == "bubbles1" {
		t.Logf("success: expected '%v', got '%v'", "bubbles1", actual)
	} else {
		t.Errorf("failed: expected '%v', got '%v'", "bubbles1", actual)
	}
}

func TestHash_01071988(t *testing.T) {
	actual := cracker.CrackSHA1Hash("80540a46a2c1a0eae58d9868f01c32bdcec9a010", false)
	if actual == "01071988" {
		t.Logf("success: expected '%v', got '%v'", "01071988", actual)
	} else {
		t.Errorf("failed: expected '%v', got '%v'", "01071988", actual)
	}
}

func TestHash_NOT_FOUND(t *testing.T) {
	actual := cracker.CrackSHA1Hash("03810a46a2c1a0eae58d9332f01c32bdcec9a01a", false)
	if actual == "PASSWORD NOT IN DATABASE" {
		t.Logf("success: expected '%v', got '%v'", "PASSWORD NOT IN DATABASE", actual)
	} else {
		t.Errorf("failed: expected '%v', got '%v'", "PASSWORD NOT IN DATABASE", actual)
	}
}

func TestSalt_superman(t *testing.T) {
	actual := cracker.CrackSHA1Hash("53d8b3dc9d39f0184144674e310185e41a87ffd5", true)
	if actual == "superman" {
		t.Logf("success: expected '%v', got '%v'", "superman", actual)
	} else {
		t.Errorf("failed: expected '%v', got '%v'", "superman", actual)
	}
}

func TestSalt_q1w2e3r4t5(t *testing.T) {
	actual := cracker.CrackSHA1Hash("da5a4e8cf89539e66097acd2f8af128acae2f8ae", true)
	if actual == "q1w2e3r4t5" {
		t.Logf("success: expected '%v', got '%v'", "q1w2e3r4t5", actual)
	} else {
		t.Errorf("failed: expected '%v', got '%v'", "q1w2e3r4t5", actual)
	}
}

func TestSalt_bubbles1(t *testing.T) {
	actual := cracker.CrackSHA1Hash("ea3f62d498e3b98557f9f9cd0d905028b3b019e1", true)
	if actual == "bubbles1" {
		t.Logf("success: expected '%v', got '%v'", "bubbles1", actual)
	} else {
		t.Errorf("failed: expected '%v', got '%v'", "bubbles1", actual)
	}
}

func TestSalt_01071988(t *testing.T) {
	actual := cracker.CrackSHA1Hash("05bbf26a28148f531cf57872df546961d1ed0861", true)
	if actual == "01071988" {
		t.Logf("success: expected '%v', got '%v'", "01071988", actual)
	} else {
		t.Errorf("failed: expected '%v', got '%v'", "01071988", actual)
	}
}

const LOOPS = 1000

func TestFaster_password_slow(t *testing.T) {
	for i := 0; i < LOOPS; i++ {
		//actual := cracker.CrackSHA1Hash("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", false)
		actual := cracker.CrackSHA1Hash("f4be2638df738981903b80deace20bfa8eb34eb7", true)
		if actual != "password" {
			t.Errorf("failed: expected %v, got %v", "password", actual)
		}
	}
}

func TestFaster_password_fast(t *testing.T) {
	for i := 0; i < LOOPS; i++ {
		actual := cracker.FasterCrackSHA1Hash("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")
		if actual != "password" {
			t.Errorf("failed: expected %v, got %v", "password", actual)
		}
	}
}

func TestFaster_password_fast_salted(t *testing.T) {
	for i := 0; i < LOOPS; i++ {
		actual := cracker.FasterCrackSHA1Hash("5a5bb2192b5991f8ce226bcbc08bc9c50d9b9ce6")
		if actual != "password" {
			//if actual != "q1w2e3r4t5" {
			//if actual != "q1w2e3r4t5" {
			t.Errorf("failed: expected %v, got %v", "password", actual)
		}
		actual2 := cracker.FasterCrackSHA1Hash("f4be2638df738981903b80deace20bfa8eb34eb7")
		if actual2 != "password" {
			//if actual != "q1w2e3r4t5" {
			//if actual != "q1w2e3r4t5" {
			t.Errorf("failed: expected %v, got %v", "password", actual2)
		}
	}
}

func TestFaster_q1w2e3r4t5_slow(t *testing.T) {
	for i := 0; i < 10; i++ {
		actual := cracker.CrackSHA1Hash("da5a4e8cf89539e66097acd2f8af128acae2f8ae", true)
		if actual != "q1w2e3r4t5" {
			t.Errorf("failed: expected %v, got %v", "q1w2e3r4t5", actual)
		}
	}
}

func TestFaster_q1w2e3r4t5_fast(t *testing.T) {
	for i := 0; i < 10*1000; i++ {
		actual := cracker.FasterCrackSHA1Hash("da5a4e8cf89539e66097acd2f8af128acae2f8ae")
		if actual != "q1w2e3r4t5" {
			t.Errorf("failed: expected %v, got %v", "q1w2e3r4t5", actual)
		}
	}
}
