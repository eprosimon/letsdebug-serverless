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

// Default to HTTP-01 validation method

const severityIcons = {
  Fatal: AlertCircle,
  Error: AlertCircle,
  Warning: AlertTriangle,
  Debug: Info
}

const severityColors = {
  Fatal: 'text-red-900 bg-red-50 border-2 border-red-400',
  Error: 'text-red-900 bg-red-50 border-2 border-red-400',
  Warning: 'text-amber-900 bg-amber-50 border-2 border-amber-400',
  Debug: 'text-blue-900 bg-blue-50 border-2 border-blue-400'
}

const severityOrder: Record<string, number> = {
  Fatal: 0,
  Error: 1,
  Warning: 2,
  Debug: 3,
}

function HomePageContent() {
  const searchParams = useSearchParams()
  const router = useRouter()
  const domainId = useId()

  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState<DebugResponse | null>(null)

  // Always use HTTP-01 validation method
  const method = 'http-01'

  // Derived results: exclude informational/debug-only items
  const relevantProblems = results?.problems.filter(p => p.severity !== 'Debug') ?? []

  // Initialize from URL params
  useEffect(() => {
    const domainParam = searchParams.get('domain')

    if (domainParam) {
      setDomain(domainParam)
    }
  }, [searchParams])

  const updateURL = (newDomain: string) => {
    const params = new URLSearchParams()
    if (newDomain) params.set('domain', newDomain)
    params.set('method', 'http-01')

    const newURL = params.toString() ? `?${params.toString()}` : '/'
    router.push(newURL, { scroll: false })
  }

  const handleDomainChange = (value: string) => {
    setDomain(value)
  }

  const handleDebug = async () => {
    if (!domain.trim()) {
      toast.error('Please enter a domain')
      return
    }

    // Update URL only on submit
    updateURL(domain.trim())

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

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    void handleDebug()
  }

  const getSeverityIcon = (severity: string) => {
    const Icon = severityIcons[severity as keyof typeof severityIcons] || Info
    return <Icon className="h-4 w-4" />
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="container mx-auto px-4 py-16 max-w-2xl">
        {/* Header */}
        <div className="text-center mb-12">
          <h1 className="text-5xl font-bold text-gray-900 mb-4">
            Let&apos;s Debug
          </h1>
          <p className="text-xl text-gray-700 leading-relaxed">
            Check your domain configuration and SSL certificate status
          </p>
        </div>

        {/* Main Form */}
        <div className="bg-white rounded-2xl shadow-lg border border-gray-200 p-8 mb-8">
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-2">
              <Label htmlFor={domainId} className="text-sm font-semibold text-gray-800">
                Domain
              </Label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <Input
                  id={domainId}
                  type="text"
                  placeholder="Enter domain (e.g., example.com)"
                  value={domain}
                  onChange={(e) => handleDomainChange(e.target.value)}
                  autoFocus
                  className="pl-10 h-12 text-base bg-white border-2 border-gray-400 focus:border-blue-600 focus:ring-0 rounded-lg text-gray-900 placeholder:text-gray-500"
                />
              </div>
            </div>
            <Button
              type="submit"
              disabled={loading || !domain.trim()}
              className="w-full h-12 text-base font-medium bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed"
            >
              {loading ? 'Checking...' : 'Check Domain'}
            </Button>
          </form>
        </div>

        {/* Results */}
        {results && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <CheckCircle className="h-5 w-5 text-green-600" />
                <span className="text-gray-900">Debug Results</span>
              </CardTitle>
              <CardDescription className="text-gray-800 font-medium">
                {relevantProblems.length === 0
                  ? 'No issues found at Warning or higher severity.'
                  : `Found ${relevantProblems.length} issue(s)`
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
                  <TabsList className="grid w-full grid-cols-4 bg-gray-100">
                    <TabsTrigger value="all" className="text-gray-700 font-medium data-[state=active]:bg-white data-[state=active]:text-gray-900">All ({relevantProblems.length})</TabsTrigger>
                    <TabsTrigger value="fatal" className="text-gray-700 font-medium data-[state=active]:bg-white data-[state=active]:text-gray-900">
                      Fatal ({relevantProblems.filter(p => p.severity === 'Fatal').length})
                    </TabsTrigger>
                    <TabsTrigger value="error" className="text-gray-700 font-medium data-[state=active]:bg-white data-[state=active]:text-gray-900">
                      Error ({relevantProblems.filter(p => p.severity === 'Error').length})
                    </TabsTrigger>
                    <TabsTrigger value="warning" className="text-gray-700 font-medium data-[state=active]:bg-white data-[state=active]:text-gray-900">
                      Warning ({relevantProblems.filter(p => p.severity === 'Warning').length})
                    </TabsTrigger>
                  </TabsList>

                  {['all', 'fatal', 'error', 'warning'].map((severity) => (
                    <TabsContent key={severity} value={severity} className="space-y-4">
                      {relevantProblems
                        .filter(p => severity === 'all' || p.severity.toLowerCase() === severity)
                        .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity])
                        .map((problem, index) => (
                          <div
                            key={`${problem.name}-${index}`}
                            className={`p-6 rounded-xl ${severityColors[problem.severity as keyof typeof severityColors]}`}
                          >
                            <div className="flex items-start gap-4">
                              {getSeverityIcon(problem.severity)}
                              <div className="flex-1">
                                <h4 className="font-bold text-lg mb-2">{problem.name}</h4>
                                <p className="text-gray-800 mb-3 leading-relaxed">{problem.explanation}</p>
                                {problem.detail && (
                                  <>
                                    <Separator className="my-3" />
                                    <details className="text-sm">
                                      <summary className="cursor-pointer font-semibold text-gray-700 hover:text-gray-900 mb-2">
                                        Technical Details
                                      </summary>
                                      <pre className="mt-2 whitespace-pre-wrap font-mono bg-white p-4 rounded-lg border border-gray-200 text-sm">
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