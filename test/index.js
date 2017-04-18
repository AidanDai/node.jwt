const path = require('path')
const expect = require('expect.js')
const jwt = require('../index')
const package = require('../package.json')

describe('jwt', function() {
	it('jwt has `version` property', function() {
		expect(jwt.version).to.be.a('string')
	})

	it('jwt has `secret` method', function() {
		expect(jwt.secret).to.be.a('function')
	})

	it('jwt has `encode` method', function() {
		expect(jwt.encode).to.be.a('function')
	})

	it('jwt has `decode` method', function() {
		expect(jwt.decode).to.be.a('function')
	})
})

describe('version', function() {
	it('the version in the library is the same as the one in package.json', function() {
		expect(jwt.version).to.equal(package.version)
	})
})

describe('secret', function() {
	it('get secret', function() {
		const secret = jwt.secret('I am a secret')

		expect(secret).to.be.a('string')
	})

	it('get secret from file', function() {
		const rsaPath = path.resolve(__dirname, './pem/private.pem')
		const secret = jwt.secret(rsaPath, true)

		expect(secret).to.be.a('object')
	})
})

describe('encode', function() {
	it('encode token with hamc algorithm and default param',function() {
		const secret = jwt.secret('I am a secret')
		const payload = {
			nbf: true,
			exp: Date.now() + 1000 * 60 * 60 * 24 * 2,
			uid: 1,
			authorization: 'authorization'
		}
		const token = jwt.encode(payload, secret)

		expect(token).to.be.a('string')
		expect(token.split('.')).to.have.length(3)
	})

	it('encode token with hamc algorithm',function() {
		const secret = jwt.secret('I am a secret')
		const payload = {
			nbf: true,
			exp: Date.now() + 1000 * 60 * 60 * 24 * 2,
			uid: 1,
			authorization: 'authorization'
		}
		const header = {
			alg: 'test',
			type: 'token',
			other: 'other'
		}
		const token = jwt.encode(payload, secret, 'HS384', header)

		expect(token).to.be.a('string')
		expect(token.split('.')).to.have.length(3)
	})

	it('encode token with rsa algorithm and default param',function() {
		const rsaPath = path.resolve(__dirname, './pem/private.pem')
		const secret = jwt.secret(rsaPath, true)
		const payload = {
			nbf: true,
			exp: Date.now() + 1000 * 60 * 60 * 24 * 2,
			uid: 1,
			authorization: 'authorization'
		}
		const token = jwt.encode(payload, secret, 'RS256')

		expect(token).to.be.a('string')
		expect(token.split('.')).to.have.length(3)
	})

	it('encode token with rsa algorithm',function() {
		const rsaPath = path.resolve(__dirname, './pem/private.pem')
		const secret = jwt.secret(rsaPath, true)
		const payload = {
			nbf: true,
			exp: Date.now() + 1000 * 60 * 60 * 24 * 2,
			uid: 1,
			authorization: 'authorization'
		}
		const header = {
			alg: 'test',
			type: 'token',
			other: 'other'
		}
		const token = jwt.encode(payload, secret, 'RS256', header)

		expect(token).to.be.a('string')
		expect(token.split('.')).to.have.length(3)
	})

	it('throw an error when the secret is missing', function() {
		const payload = {
			nbf: true,
			exp: Date.now() + 1000 * 60 * 60 * 24 * 2,
			uid: 1,
			authorization: 'authorization'
		}
    const fn = jwt.encode.bind(null, payload)

    expect(fn).to.throwError(/Require secret/)
  })

  it('throw an error when the specified algorithm is not supported', function() {
		const payload = {
			nbf: true,
			exp: Date.now() + 1000 * 60 * 60 * 24 * 2,
			uid: 1,
			authorization: 'authorization'
		}
		const secret = jwt.secret('I am a secret')
    const fn = jwt.encode.bind(null, payload, secret, 'fuck')

    expect(fn).to.throwError(/Algorithm not supported/)
  })

  it('throw an error when the secret is unvalid', function() {
		const payload = {
			nbf: true,
			exp: Date.now() + 1000 * 60 * 60 * 24 * 2,
			uid: 1,
			authorization: 'authorization'
		}
		const secret = jwt.secret('I am a secret')
    const fn = jwt.encode.bind(null, payload, secret, 'RS256')

    expect(fn).to.throwError(/Unvalid private secret for rsa sign/)
  })
})

describe('decode', function() {
	it('No token supplied', function() {
		const secret = jwt.secret('I am a secret')
		const result = jwt.decode(false, secret)

		expect(result).to.be.a('object')
		expect(result.code).to.equal('004')
		expect(result.message).to.equal('No token supplied')
	})

	it('Not enough or too many segments', function() {
		const token = 'xxxxxxxx.yyyyyyyy'
		const secret = jwt.secret('I am a secret')
		const result = jwt.decode(token, secret)

		expect(result).to.be.a('object')
		expect(result.code).to.equal('005')
		expect(result.message).to.equal('Not enough or too many segments')
	})

	it('Unvalid public secret for rsa verify, signature verification failed', function() {
		const payload = {
			nbf: true,
			exp: 1000 * 60 * 60 * 24 * 2,
			uid: 1,
			authorization: 'authorization'
		}
		const privateRsaPath = path.resolve(__dirname, './pem/private.pem')
		const privateSecret = jwt.secret(privateRsaPath, true)
		const publicSecret = jwt.secret('I am public secret')
    const token = jwt.encode(payload, privateSecret, 'RS256')
    const result = jwt.decode(token, publicSecret)

		expect(result).to.be.a('object')
		expect(result.code).to.equal('006')
		expect(result.message).to.equal('Unvalid public secret for rsa verify, signature verification failed')
	})

	it('Token expired, signature verification failed', function() {
		const payload = {
			exp: 1000,
			uid: 1,
			authorization: 'authorization'
		}
		const privateRsaPath = path.resolve(__dirname, './pem/private.pem')
		const publicRsaPath = path.resolve(__dirname, './pem/public.pem')
		const privateSecret = jwt.secret(privateRsaPath, true)
		const publicSecret = jwt.secret(publicRsaPath, true)
    const token = jwt.encode(payload, privateSecret, 'RS256')
    const result = jwt.decode(token, publicSecret)

		expect(result).to.be.a('object')
		expect(result.code).to.equal('007')
		expect(result.message).to.equal('Token expired, signature verification failed')
	})

	it('Sha decode successful', function() {
		const payload = {
			exp: 100000 * 100000 * 100000,
			uid: 1,
			authorization: 'authorization'
		}
		const secret = jwt.secret('I am a secret')
    const token = jwt.encode(payload, secret, 'HS256')
    const result = jwt.decode(token, secret)

		expect(result).to.be.a('object')
		expect(result.code).to.equal('000')
		expect(result.message).to.equal('successful')
		expect(JSON.stringify(result.payload)).to.equal(JSON.stringify(payload))
	})

	it('Rsa decode successful', function() {
		const payload = {
			exp: 100000 * 100000 * 100000,
			uid: 1,
			authorization: 'authorization'
		}
		const privateRsaPath = path.resolve(__dirname, './pem/private.pem')
		const publicRsaPath = path.resolve(__dirname, './pem/public.pem')
		const privateSecret = jwt.secret(privateRsaPath, true)
		const publicSecret = jwt.secret(publicRsaPath, true)
    const token = jwt.encode(payload, privateSecret, 'RS256')
    const result = jwt.decode(token, publicSecret)

		expect(result).to.be.a('object')
		expect(result.code).to.equal('000')
		expect(result.message).to.equal('successful')
		expect(JSON.stringify(result.payload)).to.equal(JSON.stringify(payload))
	})
})