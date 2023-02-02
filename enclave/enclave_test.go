package enclave

import (
	"flag"
	"os"
	"testing"

	"github.com/findy-network/findy-agent-auth/user"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

const dbFilename = "fido-enclave.bolt"

const emailAddress = "test@email.com"
const emailNotCreated = "not@exists.email"

func TestMain(m *testing.M) {
	try.To(flag.Set("logtostderr", "true"))
	try.To(flag.Set("v", "3"))

	setUp()
	code := m.Run()
	tearDown()
	os.Exit(code)
}

func setUp() {
	_ = os.RemoveAll(dbFilename)
	_ = InitSealedBox(dbFilename, "", "")
}

func tearDown() {
	WipeSealedBox()
}

func TestNewUser(t *testing.T) {
	assert.PushTester(t)
	defer assert.PopTester()
	u := user.NewUser(emailAddress, emailAddress, "")
	err := PutUser(u)
	assert.NoError(err)

	err = PutUser(u)
	assert.NoError(err)
}

func TestGetUser(t *testing.T) {
	assert.PushTester(t)
	defer assert.PopTester()
	u, found, err := GetUser(emailAddress)
	assert.NoError(err)
	assert.That(found)
	assert.NotNil(u)

	_, found, err = GetUser(emailNotCreated)
	assert.NoError(err)
	assert.ThatNot(found)
}

func TestGetExistingUser(t *testing.T) {
	assert.PushTester(t)
	defer assert.PopTester()
	u, err := GetExistingUser(emailAddress)
	assert.NoError(err)
	assert.NotNil(u)

	_, err = GetExistingUser(emailNotCreated)
	assert.Error(err)
}

func TestRemoveUser(t *testing.T) {
	assert.PushTester(t)
	defer assert.PopTester()

	const userToRemove = "remove@example.com"

	u := user.NewUser(userToRemove, userToRemove, "")
	err := PutUser(u)
	assert.NoError(err)
	assert.NotNil(u)

	err = RemoveUser(userToRemove)
	assert.NoError(err)

	_, err = GetExistingUser(userToRemove)
	assert.Error(err)

	err = RemoveUser(emailNotCreated)
	assert.Error(err)
}
