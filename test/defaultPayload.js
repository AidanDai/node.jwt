const path = require('path')
const expect = require('expect.js')
const jwt = require('../index')

const secret = jwt.secret('I am a secret for testing...')

const TEST_DATA_1 = 'test data'
const TEST_DATA_2 = 600
const JTI_SAMPLE_SIZE = 10000

describe('default payload', function() {

	it('it is OK not to pass a default payload',function() {
		const payload = {
      test: true
		}
    const token = jwt.encode(payload, secret)
    const result = jwt.decode(token, secret)

		expect(result).to.be.a('object')
		expect(result.code).to.equal('000')
		expect(result.message).to.equal('successful')
		expect(JSON.stringify(result.payload)).to.equal(JSON.stringify(payload))

	})

  it('it is OK to pass an empty default payload',function() {
		const payload = {
      test: true
		}
    const token = jwt.encode(payload, secret, 'HS256', { type: 'JWT' }, {} )
    const result = jwt.decode(token, secret)

		expect(result).to.be.a('object')
		expect(result.code).to.equal('000')
		expect(result.message).to.equal('successful')
		expect(JSON.stringify(result.payload)).to.equal(JSON.stringify(payload))

	})

  it('will not override existing payload variables',function() {
		const payload = {
      test: true
		}
    const defaultPayload = {
      test: false
    }
    const token = jwt.encode(payload, secret, 'HS256', { type: 'JWT' }, defaultPayload )
    const result = jwt.decode(token, secret)

		expect(result).to.be.a('object')
		expect(result.code).to.equal('000')
		expect(result.message).to.equal('successful')
		expect(JSON.stringify(result.payload)).to.equal(JSON.stringify(payload))
	})

  it('will add non-reserved claims to payload as is',function() {
		const payload = {
      test: true
		}
    const defaultPayload = {
      testDefaultString: TEST_DATA_1
    }
    expect(payload.testDefaultString).to.be.a('undefined')
    const token = jwt.encode(payload, secret, 'HS256', { type: 'JWT' }, defaultPayload )
    expect(payload.testDefaultString).to.be.a('string')
    expect(payload.testDefaultString).to.equal(TEST_DATA_1)
    const result = jwt.decode(token, secret)
		expect(result).to.be.a('object')
		expect(result.code).to.equal('000')
		expect(result.message).to.equal('successful')
    expect(result.payload.testDefaultString).to.be.a('string')
    expect(result.payload.testDefaultString).to.equal(TEST_DATA_1)
		expect(JSON.stringify(result.payload)).to.equal(JSON.stringify(payload))
	})

  it('will not add jti if default payload has jti as false',function() {
		const payload = {
      test: true
		}
    const defaultPayload = {
      jti: false
    }
    expect(payload.jti).to.be.a('undefined')
    const token = jwt.encode( payload, secret, 'HS256', { type: 'JWT' }, defaultPayload )
    expect(payload.jti).to.be.a('undefined')
    const result = jwt.decode(token, secret)
		expect(result).to.be.a('object')
		expect(result.code).to.equal('000')
		expect(result.message).to.equal('successful')
    expect(result.payload.jti).to.be.a('undefined')
		expect(JSON.stringify(result.payload)).to.equal(JSON.stringify(payload))
	})

  it('will add jti if default payload has jti as true',function() {
    const payload = {
      test: true
    }
    const defaultPayload = {
      jti: true
    }
    expect(payload.jti).to.be.a('undefined')
    const token = jwt.encode(payload, secret, 'HS256', { type: 'JWT' }, defaultPayload )
    expect(payload.jti).to.be.a('string')
    const result = jwt.decode(token, secret)
    expect(result).to.be.a('object')
    expect(result.code).to.equal('000')
    expect(result.message).to.equal('successful')
    expect(result.payload.jti).to.be.a('string')
    expect(JSON.stringify(result.payload)).to.equal(JSON.stringify(payload))
  })

  it('unique default jti identifiers (sample size ' + JTI_SAMPLE_SIZE + ')',function() {
    const defaultPayload = {
      jti: true
    }
    var jtiSample = new Array()
    for (var i=0; i<JTI_SAMPLE_SIZE; i++) { // 10,000 TOKENS IN A 48 HOUR EXPIRY WINDOWN, ARE THERE ANY COLLISIONS? NOT A GREAT TEST BUT BETTER THAN NOTHING?
      const payload = {
        test: true
      }
      var token = jwt.encode(payload, secret, 'HS256', { type: 'JWT' }, defaultPayload )
      var result = jwt.decode(token, secret)
      jtiSample[jtiSample.length] = result.payload.jti
    }
    jtiSample.sort()
    var compare = false
    for (var i=0; !compare && i<jtiSample.length-1; i++ ) {
      compare = ( jtiSample[i]==jtiSample[i+1] )
    }
    expect (compare).to.equal(false)
  })

  it('can be passed a jti identifier function',function() {
    const payload = {
      test: true
    }
    const defaultPayload = {
      jti: function(){
        return TEST_DATA_1 + TEST_DATA_1
      }
    }
    var token = jwt.encode(payload, secret, 'HS256', { type: 'JWT' }, defaultPayload )
    var result = jwt.decode(token, secret)
    expect(result).to.be.a('object')
    expect(result.code).to.equal('000')
    expect(result.message).to.equal('successful')
    expect(result.payload.jti).to.be.a('string')
    expect(result.payload.jti).to.equal(TEST_DATA_1 + TEST_DATA_1)
  })

  it('will set the Expiry claim if exp is set to an integer',function() {
    const payload = {
      test: true
    }
    const defaultPayload = {
      exp: TEST_DATA_2
    }
    expect(payload.exp).to.be.a('undefined')
    var token = jwt.encode(payload, secret, 'HS256', { type: 'JWT' }, defaultPayload )
    expect(payload.exp).to.be.a('number')
    var result = jwt.decode(token, secret)
    expect(result).to.be.a('object')
    expect(result.code).to.equal('000')
    expect(result.message).to.equal('successful')
    expect(result.payload.exp).to.be.a('number')
    var expectedUnixDate = (new Date()).getTime()/1000 + TEST_DATA_2
    expect( result.payload.exp ).to.be.greaterThan( expectedUnixDate-2000 )
    expect( result.payload.exp ).to.be.lessThan( expectedUnixDate+2000 )
  })

  it('will set the Issued At claim if iat is set to an integer',function() {
    const payload = {
      test: true
    }
    const defaultPayload = {
      iat: TEST_DATA_2
    }
    expect(payload.iat).to.be.a('undefined')
    var token = jwt.encode(payload, secret, 'HS256', { type: 'JWT' }, defaultPayload )
    expect(payload.iat).to.be.a('number')
    var result = jwt.decode(token, secret)
    expect(result).to.be.a('object')
    expect(result.code).to.equal('000')
    expect(result.message).to.equal('successful')
    expect(result.payload.iat).to.be.a('number')
    var expectedUnixDate = (new Date()).getTime()/1000 + TEST_DATA_2
    expect( result.payload.iat ).to.be.greaterThan( expectedUnixDate-2000 )
    expect( result.payload.iat ).to.be.lessThan( expectedUnixDate+2000 )
  })

  it('will set the Not Before claim if nbf is set to an integer',function() {
    const payload = {
      test: true
    }
    const defaultPayload = {
      nbf: TEST_DATA_2
    }
    expect(payload.nbf).to.be.a('undefined')
    var token = jwt.encode(payload, secret, 'HS256', { type: 'JWT' }, defaultPayload )
    expect(payload.nbf).to.be.a('number')
    var result = jwt.decode(token, secret)
    expect(result).to.be.a('object')
    expect(result.code).to.equal('000')
    expect(result.message).to.equal('successful')
    expect(result.payload.nbf).to.be.a('number')
    var expectedUnixDate = (new Date()).getTime()/1000 - TEST_DATA_2 // IN THE PAST
    expect( result.payload.nbf ).to.be.greaterThan( expectedUnixDate-2000 )
    expect( result.payload.nbf ).to.be.lessThan( expectedUnixDate+2000 )
  })

	it('will only accept default payload exp as an integer',function() {
		const payload = {
			test: true
		}
		const defaultPayload = {
			exp: 123.123
		}
		expect(payload.nbf).to.be.a('undefined')
		var badFunction = function() {
			jwt.encode(payload, secret, 'HS256', { type: 'JWT' }, defaultPayload )
		}
		expect(badFunction).to.throwError()
	})

	it('will only accept default payload iat as an integer',function() {
    const payload = {
      test: true
    }
    const defaultPayload = {
      nbf: true
    }
    expect(payload.nbf).to.be.a('undefined')
    var badFunction = function() {
      jwt.encode(payload, secret, 'HS256', { type: 'JWT' }, defaultPayload )
    }
    expect(badFunction).to.throwError()
  })

  it('will only accept default payload nbf as an integer',function() {
    const payload = {
      test: true
    }
    const defaultPayload = {
      nbf: 'banana'
    }
    expect(payload.nbf).to.be.a('undefined')
    var badFunction = function() {
      jwt.encode(payload, secret, 'HS256', { type: 'JWT' }, defaultPayload )
    }
    expect(badFunction).to.throwError()
  })

})
