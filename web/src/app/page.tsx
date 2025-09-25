'use client'

import { useState, useEffect, useId, Suspense } from 'react'
import { useSearchParams, useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Separator } from '@/components/ui/separator'
import { Search, AlertCircle, CheckCircle, Info, AlertTriangle } from 'lucide-react'
import { toast } from 'sonner'

interface Problem {
  name: string
  explanation: string
  detail: string
  severity: 'Fatal' | 'Error' | 'Warning' | 'Debug'
}

interface DebugResponse {
  problems: Problem[]
  error?: string
}

const validationMethods = [
  { value: 'http-01', label: 'HTTP-01' },
  { value: 'dns-01', label: 'DNS-01' },
  { value: 'tls-alpn-01', label: 'TLS-ALPN-01' }
]

const severityIcons = {
  Fatal: AlertCircle,
  Error: AlertCircle,
  Warning: AlertTriangle,
  Debug: Info
}

const severityColors = {
  Fatal: 'text-red-600 bg-red-50 border-red-200',
  Error: 'text-red-600 bg-red-50 border-red-200',
  Warning: 'text-yellow-600 bg-yellow-50 border-yellow-200',
  Debug: 'text-blue-600 bg-blue-50 border-blue-200'
}

function HomePageContent() {
  const searchParams = useSearchParams()
  const router = useRouter()
  const domainId = useId()
  
  const [domain, setDomain] = useState('')
  const [method, setMethod] = useState('http-01')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState<DebugResponse | null>(null)

  // Initialize from URL params
  useEffect(() => {
    const domainParam = searchParams.get('domain')
    const methodParam = searchParams.get('method')
    
    if (domainParam) {
      setDomain(domainParam)
    }
    if (methodParam && validationMethods.some(m => m.value === methodParam)) {
      setMethod(methodParam)
    }
  }, [searchParams])

  const updateURL = (newDomain: string, newMethod: string) => {
    const params = new URLSearchParams()
    if (newDomain) params.set('domain', newDomain)
    if (newMethod) params.set('method', newMethod)
    
    const newURL = params.toString() ? `?${params.toString()}` : '/'
    router.push(newURL, { scroll: false })
  }

  const handleDomainChange = (value: string) => {
    setDomain(value)
    updateURL(value, method)
  }

  const handleMethodChange = (value: string) => {
    setMethod(value)
    updateURL(domain, value)
  }

  const handleDebug = async () => {
    if (!domain.trim()) {
      toast.error('Please enter a domain')
      return
    }

    setLoading(true)
    setResults(null)

    try {
      const response = await fetch('/api/debug', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          domain: domain.trim(),
          method
        })
      })

      const data: DebugResponse = await response.json()
      setResults(data)

      if (data.error) {
        toast.error(`Debug failed: ${data.error}`)
      } else if (data.problems.length === 0) {
        toast.success('No issues found! Domain looks good for Let&apos;s Encrypt.')
      } else {
        const fatalCount = data.problems.filter(p => p.severity === 'Fatal').length
        const errorCount = data.problems.filter(p => p.severity === 'Error').length
        const warningCount = data.problems.filter(p => p.severity === 'Warning').length
        
        if (fatalCount > 0) {
          toast.error(`Found ${fatalCount} fatal issue(s)`)
        } else if (errorCount > 0) {
          toast.error(`Found ${errorCount} error(s)`)
        } else if (warningCount > 0) {
          toast.warning(`Found ${warningCount} warning(s)`)
        } else {
          toast.info(`Found ${data.problems.length} debug message(s)`)
        }
      }
    } catch (error) {
      toast.error('Failed to debug domain')
      console.error('Debug error:', error)
    } finally {
      setLoading(false)
    }
  }

  const getSeverityIcon = (severity: string) => {
    const Icon = severityIcons[severity as keyof typeof severityIcons] || Info
    return <Icon className="h-4 w-4" />
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2">
            Let&apos;s Debug
          </h1>
          <p className="text-lg text-gray-600">
            Diagnose Let&apos;s Encrypt certificate issuance issues
          </p>
        </div>

        {/* Main Form */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle>Domain Debug Tool</CardTitle>
            <CardDescription>
              Enter a domain to check for potential Let&apos;s Encrypt certificate issuance issues
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor={domainId}>Domain</Label>
                <Input
                  id={domainId}
                  type="text"
                  placeholder="example.com"
                  value={domain}
                  onChange={(e) => handleDomainChange(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleDebug()}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="method">Validation Method</Label>
                <Select value={method} onValueChange={handleMethodChange}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {validationMethods.map((method) => (
                      <SelectItem key={method.value} value={method.value}>
                        {method.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <Button 
              onClick={handleDebug} 
              disabled={loading || !domain.trim()}
              className="w-full md:w-auto"
            >
              <Search className="h-4 w-4 mr-2" />
              {loading ? 'Debugging...' : 'Debug Domain'}
            </Button>
          </CardContent>
        </Card>

        {/* Results */}
        {results && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <CheckCircle className="h-5 w-5 text-green-600" />
                Debug Results
              </CardTitle>
              <CardDescription>
                {results.problems.length === 0 
                  ? 'No issues found! Your domain should work with Let&apos;s Encrypt.'
                  : `Found ${results.problems.length} issue(s)`
                }
              </CardDescription>
            </CardHeader>
            <CardContent>
              {results.error ? (
                <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
                  <p className="text-red-800 font-medium">Error:</p>
                  <p className="text-red-700">{results.error}</p>
                </div>
              ) : results.problems.length === 0 ? (
                <div className="p-4 bg-green-50 border border-green-200 rounded-lg">
                  <p className="text-green-800 font-medium">✅ All checks passed!</p>
                  <p className="text-green-700">Your domain appears to be properly configured for Let&apos;s Encrypt certificate issuance.</p>
                </div>
              ) : (
                <Tabs defaultValue="all" className="w-full">
                  <TabsList className="grid w-full grid-cols-4">
                    <TabsTrigger value="all">All ({results.problems.length})</TabsTrigger>
                    <TabsTrigger value="fatal">
                      Fatal ({results.problems.filter(p => p.severity === 'Fatal').length})
                    </TabsTrigger>
                    <TabsTrigger value="error">
                      Error ({results.problems.filter(p => p.severity === 'Error').length})
                    </TabsTrigger>
                    <TabsTrigger value="warning">
                      Warning ({results.problems.filter(p => p.severity === 'Warning').length})
                    </TabsTrigger>
                  </TabsList>
                  
                  {['all', 'fatal', 'error', 'warning'].map((severity) => (
                    <TabsContent key={severity} value={severity} className="space-y-4">
                      {results.problems
                        .filter(p => severity === 'all' || p.severity.toLowerCase() === severity)
                        .map((problem, index) => (
                          <div
                            key={`${problem.name}-${index}`}
                            className={`p-4 rounded-lg border ${severityColors[problem.severity as keyof typeof severityColors]}`}
                          >
                            <div className="flex items-start gap-3">
                              {getSeverityIcon(problem.severity)}
                              <div className="flex-1">
                                <h4 className="font-semibold mb-1">{problem.name}</h4>
                                <p className="text-sm mb-2">{problem.explanation}</p>
                                {problem.detail && (
                                  <>
                                    <Separator className="my-2" />
                                    <details className="text-xs">
                                      <summary className="cursor-pointer font-medium">Technical Details</summary>
                                      <pre className="mt-2 whitespace-pre-wrap font-mono bg-white/50 p-2 rounded">
                                        {problem.detail}
                                      </pre>
                                    </details>
                                  </>
                                )}
                              </div>
                            </div>
                          </div>
                        ))}
                    </TabsContent>
                  ))}
                </Tabs>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}

export default function HomePage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
      <div className="text-center">
        <h1 className="text-4xl font-bold text-gray-900 mb-2">Let&apos;s Debug</h1>
        <p className="text-lg text-gray-600">Loading...</p>
      </div>
    </div>}>
      <HomePageContent />
    </Suspense>
  )
}