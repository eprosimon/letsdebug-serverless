// Simple test script for the Go API
const testAPI = async () => {
  try {
    const response = await fetch('http://localhost:3001/api/debug', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        domain: 'example.com',
        method: 'http-01'
      })
    });

    const data = await response.json();
    console.log('API Response:', JSON.stringify(data, null, 2));
  } catch (error) {
    console.error('API Test Error:', error);
  }
};

// Run the test
testAPI();
