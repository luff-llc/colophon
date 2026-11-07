#!/usr/bin/env python3
"""Generate the Swift payload/query surface from core schemas; result shapes are below.
Run: cargo run -q -p colophon-core --example swift_schema > /tmp/schemas.json
     python3 scripts/generate-swift-domains.py /tmp/schemas.json
No generation is performed at app build time. The core remains the validator.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULES = [('Books', 'reading.books'), ('Listening', 'listening.podcasts'), ('Saved', 'reading.saved'), ('Notes', 'notes')]
def upper(s): return s[0].upper()+s[1:]
def enum_case(s):
    parts=re.split(r'[^a-zA-Z0-9_]',s)
    return parts[0]+''.join(upper(p) for p in parts[1:] if p)

def ident(s): return '`'+s+'`' if s in {'extension','repeat','default','case','self','init','operator','static','class','protocol','where','associatedtype','in','is','as','return','nil','true','false'} else s

class Generator:
    def __init__(self): self.models={}; self.seen={}
    def swift_type(self, schema, name):
        schema=dict(schema)
        t=schema.get('type')
        if isinstance(t,list):
            nonnull=[v for v in t if v!='null']; schema['type']=nonnull[0]
            return 'DomainNullable<'+self.swift_type(schema,name)+'>'
        variants=schema.get('oneOf',schema.get('anyOf'))
        if variants:
            nonnull=[s for s in variants if s.get('type')!='null']
            if len(nonnull)!=len(variants):
                if len(nonnull)==1: return 'DomainNullable<'+self.swift_type(nonnull[0],name)+'>'
                return 'DomainNullable<'+self.swift_type({'oneOf':nonnull},name)+'>'
            key=json.dumps(schema,sort_keys=True)
            if key in self.seen: return self.seen[key]
            self.seen[key]=name
            cases=[]
            for i,v in enumerate(variants):
                discriminator=v.get('properties',{}).get('kind',{}).get('const')
                case=discriminator or ('variant'+str(i+1))
                cases.append((case,self.swift_type(v,name+upper(case))))
            lines=[f'public enum {name}: Codable, Hashable, Sendable {{']
            for case,ty in cases: lines.append(f'    case {ident(case)}({ty})')
            lines+=['    public init(from decoder: any Decoder) throws {','        let c = try decoder.singleValueContainer()']
            for case,ty in cases: lines.append(f'        if let value = try? c.decode({ty}.self) {{ self = .{ident(case)}(value); return }}')
            lines+=['        throw DecodingError.dataCorruptedError(in: c, debugDescription: "Unknown domain variant")','    }','    public func encode(to encoder: any Encoder) throws {','        var c = encoder.singleValueContainer()','        switch self {']
            for case,_ in cases: lines.append(f'        case .{ident(case)}(let value): try c.encode(value)')
            lines+=['        }','    }','}']; self.models[name]='\n'.join(lines);return name
        if 'enum' in schema and all(isinstance(v,str) for v in schema['enum']):
            key=json.dumps(schema['enum'])
            if key in self.seen:return self.seen[key]
            self.seen[key]=name
            self.models[name]=f'public enum {name}: String, Codable, Hashable, Sendable {{\n'+''.join(f'    case {ident(enum_case(v))} = {json.dumps(v)}\n' for v in schema['enum'])+'}'
            return name
        if 'const' in schema:
            v=schema['const']
            if isinstance(v,str): return self.swift_type({'type':'string','enum':[v]},name)
            return 'Int'
        if t=='array':return '['+self.swift_type(schema.get('items',{}),name+'Element')+']'
        if t=='object' or 'properties' in schema:
            if not schema.get('properties'):
                return '[String: '+self.swift_type(schema.get('additionalProperties') if isinstance(schema.get('additionalProperties'),dict) else {},name+'Value')+']'
            key=json.dumps(schema,sort_keys=True)
            if key in self.seen:return self.seen[key]
            self.seen[key]=name
            self.struct(name,schema)
            return name
        return {'string':'String','integer':'Int','number':'Double','boolean':'Bool','null':'DomainJSON'}.get(t,'DomainJSON')
    def struct(self,name,schema,conformance=None,statics='',extras=True,types=None):
        required=schema.get('required',[]); props=schema.get('properties',{})
        fields=[]
        for k,v in props.items():
            ty=types[k] if types and k in types else self.swift_type(v,name+upper(k))
            optional=k not in required
            fields.append((k,ty,optional))
        lines=[f'public struct {name}: {conformance or "Codable, Hashable, Sendable"} {{']
        if statics:lines.extend('    '+l for l in statics.splitlines())
        for k,ty,opt in fields:lines.append(f'    public var {ident(k)}: {ty}'+('?' if opt else ''))
        if extras:lines.append('    public var additionalFields: [String: DomainJSON]')
        args=[f'{ident(k)}: {ty}'+('? = nil' if opt else '') for k,ty,opt in fields]
        if extras:args+=['additionalFields: [String: DomainJSON] = [:]']
        lines.append('    public init('+', '.join(args)+') {')
        for k,_,_ in fields:lines.append(f'        self.{ident(k)} = {ident(k)}')
        if extras:lines.append('        self.additionalFields = additionalFields')
        lines+=['    }','    public init(from decoder: any Decoder) throws {','        let c = try decoder.container(keyedBy: DomainCodingKey.self)']
        for k,ty,opt in fields:
            # contains, rather than decodeIfPresent, keeps explicit null distinct from omission.
            expr=f'try c.decode({ty}.self, forKey: .init("{k}"))'
            if opt:expr=f'c.contains(.init("{k}")) ? {expr} : nil'
            lines.append(f'        {ident(k)} = {expr}')
        if extras:
            lines+=['        additionalFields = [:]',f'        let known: Set<String> = [{", ".join(json.dumps(k) for k,_,_ in fields)}]','        for key in c.allKeys where !known.contains(key.stringValue) {','            additionalFields[key.stringValue] = try c.decode(DomainJSON.self, forKey: key)','        }']
        lines+=['    }','    public func encode(to encoder: any Encoder) throws {','        var c = encoder.container(keyedBy: DomainCodingKey.self)']
        if extras:
            lines += [f'        let known: Set<String> = [{", ".join(json.dumps(k) for k,_,_ in fields)}]','        for (key, value) in additionalFields where !known.contains(key) { try c.encode(value, forKey: .init(key)) }']
        for k,_,opt in fields:lines.append(f'        try c.encode{"IfPresent" if opt else ""}({ident(k)}, forKey: .init("{k}"))')
        lines+=['    }','}'];self.models[name]='\n'.join(lines)
        if not fields and not extras:
            self.models[name]=self.models[name].replace('let c = try decoder.container', '_ = try decoder.container').replace('var c = encoder.container', '_ = encoder.container')

# Explicit result contracts follow the implemented reducers, including nullable fields and
# bounded previews. Only genuinely open JSON (extensions, alternatives, provenance) stays JSON.
RESULTS = {}
QUERIES = {}
def models(domain, definitions, queries):
    RESULTS[domain]={}
    for line in definitions.strip().splitlines():
        name,fields=line.strip().split(' ',1)
        RESULTS[domain][name]=dict(field.split(':',1) for field in fields.split())
    QUERIES[domain]=dict(pair.split(':',1) for pair in queries.split())

models('Books', '''
BookRow id:String title:String creator:String isbn:String? coverID:Int? status:String page:Int? pages:Int? fraction:Double started:String? finished:String? noteCount:Int conflictCount:Int revision:String
BookDetail book:BookValue heads:BookHeads currentReading:ReadingRow loan:LoanValue? extensions:[String:DomainJSON]
BookValue id:String title:String creator:String isbn:String? catalogKey:String? pages:Int? coverID:Int? publicationYear:Int? fraction:Double? page:Int? revision:String author:String authorLabel:String origin:String clock:Int
BookHeads metadata:String? plan:String? progress:String? loan:String? activity:String?
LoanValue status:String requestID:String reflection:String? proposal:DomainJSON? revision:String? author:String? authorLabel:String? origin:String? clock:Int?
ReadingRow id:String status:String started:String? finished:String? revision:String
BookCounts total:Int byStatus:[String:Int] finishedYears:[FinishedYearCount] conflicts:Int
FinishedYearCount year:Int? count:Int
BookNoteRow id:String textPreview:String quotePreview:String? location:String? revision:String alternativeCount:Int authorLabel:String truncated:Bool?
NoteDetail note:Attribution text:String quote:String? location:String? book:String alternativeCount:Int extensions:[String:DomainJSON]
Membership key:String bookIDs:[String] total:Int truncated:Bool?
''','books:DomainPage<BookRow> book:BookDetail bookCounts:BookCounts bookNotes:DomainPage<BookNoteRow> note:NoteDetail readings:DomainPage<ReadingRow> catalogMembership:[Membership] conflicts:DomainPage<ConflictRow> invalid:DomainPage<DiagnosticRow>')
models('Listening','''
ShowRow id:String title:String url:String following:Bool revision:String
ShowValue id:String title:String url:String following:Bool revision:String author:String authorLabel:String origin:String clock:Int skipIntro:Double? skipOutro:Double? extensions:[String:DomainJSON]?
ShowDetail show:ShowValue skipIntro:Double? skipOutro:Double? episodeCount:Int
EpisodeRow id:String show:String? title:String? showTitle:String? seconds:Double duration:Double? consumption:String? updated:String? positionRevision:String? stateRevision:String? metadataAvailable:Bool transcriptAvailable:Bool noteCount:Int positionBaseline:Bool? stateBaseline:Bool?
EpisodeDetail row:EpisodeRow metadata:EpisodeMetadata? heads:EpisodeHeads extensions:[String:DomainJSON]
EpisodeMetadata id:String? episode:String? show:String? feed:String? guid:String? title:String? showTitle:String? audioURL:String? duration:Double? published:String? transcriptExcerpt:String?
EpisodeHeads metadata:String? position:String? state:String?
QueuePage head:String? page:DomainPage<EpisodeRow>
PlaybackContext episode:EpisodeRow queueHead:String? next:EpisodeRow? preferences:[String:DomainJSON] preferenceHeads:[String:String] segmentHead:String? chapterHead:String? transcriptID:String?
PlaylistRow id:String name:String mode:String revision:String alternativeCount:Int
PlaylistDetail rule:PlaylistRule revision:String alternativeCount:Int extensions:[String:DomainJSON]?
PlaylistRule id:String name:String mode:String allShows:Bool includeFinished:Bool archived:Bool shows:[String] episodes:[String] excluded:[String] pinned:[String] included:[String] order:String progress:String maxMinutes:Int? titleContains:String?
PodcastNoteRow id:String episode:String seconds:Double? textPreview:String quotePreview:String? revision:String creationRevision:String created:String? authorLabel:String origin:String anchorClaimed:Bool alternativeCount:Int truncated:Bool?
NoteDetail note:Attribution text:String quote:String? anchor:TranscriptAnchor? capture:CaptureDescriptor? creationRevision:String creation:Attribution? lastTextEditor:Attribution alternativeCount:Int
TranscriptReference transcript:String revision:String blob:BlobDescriptor episode:String? show:String? libraryID:String?
TranscriptAnchor reference:TranscriptReference startUTF16:Int lengthUTF16:Int quote:String
CaptureDescriptor requestID:String originalText:String voice:BlobDescriptor? voiceMimeType:String? surroundingText:String? targetAgentID:String?
RecordingPage head:String? source:String? contentOrigin:String? page:DomainPage<RecordingRow>
RecordingSummary episode:String show:String? recording:String kind:String head:String? source:String? contentOrigin:String? personReviewed:Bool? count:Int
PreferenceRow key:String scope:String target:String? field:String value:DomainJSON? revision:String author:String authorLabel:String origin:String
RecordingRow id:String start:Double end:Double? kind:String? title:String?
TranscriptRow id:String episode:String blob:BlobDescriptor source:String timed:Bool recording:String? language:String? selected:Bool revision:String sourceStatus:String?
JobRow id:String kind:String requestRevision:String worker:String? status:String responseRevision:String? sourceRefs:DomainJSON? deadline:String?
ContributionRow id:String textPreview:String? question:String? reference:TranscriptReference? proposalRevision:String? acceptanceRevision:String? author:String origin:String sourceStatus:String? claimCount:Int? truncated:Bool?
ContributionDetail id:String kind:String? question:String? text:String? claims:[AnswerClaim]? reference:TranscriptReference? proposalRevision:String? acceptanceRevision:String? author:String? origin:String? sourceStatus:String?
AnswerClaim text:String citations:[TranscriptAnchor]
ListeningCounts followed:Int episodes:Int inProgress:Int finished:Int queued:Int notes:Int transcripts:Int pendingJobs:Int conflicts:Int
''','shows:DomainPage<ShowRow> show:ShowDetail episodes:DomainPage<EpisodeRow> getEpisode:EpisodeDetail getQueue:QueuePage playbackContext:PlaybackContext playlists:DomainPage<PlaylistRow> playlist:PlaylistDetail notes:DomainPage<PodcastNoteRow> note:NoteDetail recordingContent:RecordingPage recordings:DomainPage<RecordingSummary> preferences:DomainPage<PreferenceRow> transcripts:DomainPage<TranscriptRow> history:DomainPage<EpisodeRow> jobs:DomainPage<JobRow> contributions:ContributionResult listeningCounts:ListeningCounts conflicts:DomainPage<ConflictRow> invalid:DomainPage<String>')
models('Notes','''
NotebookRow id:String title:String kind:String topic:String? touched:FoldOrder entryCount:Int cellCount:Int revision:String created:String? updated:String?
NotebookDetail id:String title:String kind:String topic:String? archived:Bool revision:String orderRevision:String? created:String? updated:String? entryCount:Int cellCount:Int materialCount:Int extensions:[String:DomainJSON]
EntryRow id:String title:String? date:String? tags:[String] touched:FoldOrder revision:String created:String? updated:String? cellCount:Int alternativeCount:Int
EntryDetail id:String current:EntryValue cellCount:Int attachmentCount:Int proposalCount:Int alternativeCount:Int
EntryValue title:String? date:String? tags:[String] revision:String author:String authorLabel:String created:String? updated:String?
CellRow id:String kind:String language:String? entry:String? sourcePreview:String revision:String alternativeCount:Int outputIsCurrent:Bool latestRun:String? truncated:Bool?
CellDetail cell:Attribution kind:String source:String language:String? entry:String? outputIsCurrent:Bool latestRun:String? extensions:[String:DomainJSON]
AttachmentRow id:String role:String name:String mime:String? blob:BlobDescriptor? source:SourceReference? revision:String authorLabel:String
SourceReference kind:String url:String? library:String? namespace:String? artifact:String? revision:String? quote:String? page:Int? seconds:Double? recording:String? extensions:[String:DomainJSON]?
ProposalRow id:String title:String? markdownPreview:String revision:String status:String inputCurrent:Bool reviewRevision:String? authorLabel:String truncated:Bool?
ContentDetail record:ContentRecord? versions:DomainPage<ConflictRow>
ContentRecord id:String notebook:String cell:String? entry:String? sourceDigest:String? runtime:String? outputs:[RunOutput]? error:String? markdown:String? inputs:[String:String]? title:String? tags:[String]? reviewedMarkdown:String? revision:String author:String authorLabel:String origin:String clock:Int
RunOutput mime:String text:String? blob:BlobDescriptor? extensions:[String:DomainJSON]?
NoteCounts notebooks:Int archived:Int entries:Int cells:Int materials:Int pendingProposals:Int conflicts:Int lateEdits:Int
''','notebooks:DomainPage<NotebookRow> notebook:NotebookDetail entries:DomainPage<EntryRow> entry:EntryDetail cells:DomainPage<CellRow> cell:CellDetail attachments:DomainPage<AttachmentRow> proposals:DomainPage<ProposalRow> contentDetail:ContentDetail noteCounts:NoteCounts conflicts:DomainPage<ConflictRow> invalid:DomainPage<DiagnosticRow>')
models('Saved','''
TextPreview text:String truncated:Bool
ItemRow id:String title:String? creator:String? url:String? kind:String consumption:String? retention:String? added:String? sourceStatus:String progress:DomainJSON? noteCount:Int conflictCount:Int revision:String touched:Int? deleted:Bool?
ItemDetail item:ItemValue heads:ItemHeads selectedSource:String? metadataOnly:Bool extensions:[String:DomainJSON]?
ItemValue id:String title:String? creator:String? summary:String? collection:String? tags:[String]? url:String? consumption:String? retention:String? added:String? revision:String author:String authorLabel:String origin:String clock:Int
ItemHeads activity:String? metadata:String? position:String? source:String? state:String?
ReadingCounts total:Int readingNow:Int unread:Int finished:Int archived:Int sourceOnly:Int notes:Int conflicts:Int deleted:Int
SourceVersion id:String original:BlobDescriptor? metadata:BlobDescriptor mediaType:String origin:DomainJSON capturedAt:String extractionVersion:Int pageCount:Int? coverage:String
ImageRow candidate:ImageCandidate blob:BlobDescriptor mime:String width:Int height:Int observedURLs:[String] capturedAt:String
ImageCandidate id:String itemID:String source:String index:Int baseURL:String? sourceURL:String alt:String afterPassageID:String?
SourceMetadata id:String item:String kind:String value:DomainJSON raw:BlobDescriptor revision:String author:String authorLabel:String origin:String clock:Int
PositionValue position:ReadingPosition? revision:String? source:String? updated:String?
ReadingPosition kind:String index:Int? id:String? offsetUTF16:Int?
AnnotationAnchor kind:String passageID:String? startUTF16:Int? lengthUTF16:Int? quote:String? index:Int? location:String? reason:String?
AnnotationRow id:String thread:String item:String source:String anchorPreview:TextPreview? textPreview:TextPreview? heads:[String] deleted:Bool conflicted:Bool authorLabel:String? tags:[String] headCount:Int headsTruncated:Bool?
AnnotationDetail current:AnnotationRevision? deleted:Bool extensions:[String:DomainJSON]? headCount:Int heads:[String] sourceStatus:String
AnnotationRevision id:String thread:String item:String source:String parents:[String] action:String anchor:AnnotationAnchor text:String revision:String author:String authorLabel:String origin:String clock:Int historical:Bool?
FeedRow id:String title:String url:String folders:[[String]] followed:Bool revision:String entryCount:Int author:String authorLabel:String origin:String clock:Int
FeedEntryRow id:String title:String url:String? publisherIdentity:String author:String summaryPreview:TextPreview published:String? response:BlobDescriptor?
SavedViewRow id:String name:String? revision:String? deleted:Bool conflicted:Bool headCount:Int
SavedViewDetail deleted:Bool conflicted:Bool headCount:Int heads:[ViewRevision]
ViewRevision id:String view:String parents:[String] name:String query:SavedViewFilter deleted:Bool revision:String author:String authorLabel:String origin:String clock:Int historical:Bool?
ReviewQueue enabled:Bool eligibleCount:Int decisionRevision:String? rows:[AnnotationRow] next:String? total:Int?
ReviewRow id:String action:String thread:String? annotation:String? undoing:String? revision:String author:String authorLabel:String origin:String clock:Int
AnswerRow id:String question:String? evidenceCount:Int? sourceStatus:String? visibilityHeads:[String]? visibilityHeadCount:Int? claimCount:Int? hidden:Bool? conflicted:Bool? revision:String? author:String? authorLabel:String? origin:String? clock:Int? truncated:Bool?
AnswerDetail answer:AnswerAttribution question:String claims:[ReadingClaim] evidence:[EvidenceReference] engine:String runtime:String promptRevision:String sourceStatus:String
AnswerAttribution id:String question:String engine:String runtime:String promptRevision:String revision:String author:String authorLabel:String origin:String clock:Int
ReadingClaim text:String citations:[EvidenceReference]
EvidenceReference source:String annotation:String? anchor:AnnotationAnchor?
ConnectionRow id:String connection:String? source:Endpoint? target:Endpoint? relation:String? reasonPreview:TextPreview? heads:[String] retracted:Bool? conflicted:Bool? headCount:Int? revision:String?
Endpoint item:String source:String annotation:String?
SubscriptionRow id:String publication:String status:String plan:String accessUntil:String? revision:String alternativeCount:Int author:String authorLabel:String origin:String clock:Int
''','items:DomainPage<ItemRow> item:ItemDetail readingCounts:ReadingCounts sources:DomainPage<SourceRow> getPosition:PositionValue? annotations:DomainPage<AnnotationRow> annotation:AnnotationDetail annotationHistory:DomainPage<AnnotationRevision> feeds:DomainPage<FeedRow> feedEntries:DomainPage<FeedEntryRow> savedViews:DomainPage<SavedViewRow> savedView:SavedViewDetail reviewQueue:ReviewQueue reviewHistory:DomainPage<ReviewRow> answers:DomainPage<AnswerRow> answer:AnswerDetail connections:DomainPage<ConnectionRow> subscriptions:DomainPage<SubscriptionRow> conflicts:DomainPage<ConflictRow> invalid:DomainPage<DiagnosticRow>')

COMMON='''
Attribution id:String? revision:String author:String authorLabel:String origin:String clock:Int
BlobDescriptor digest:String size:Int mediaType:String
ConflictRow operation:String? revision:String? id:String? component:String expected:DomainJSON? found:DomainJSON? candidate:DomainJSON author:String? authorLabel:String? origin:String? clock:Int? historical:Bool outcome:String? reason:String? resolved:Bool? attribution:ConflictAttribution?
ConflictAttribution author:String authorLabel:String origin:String clock:Int
DiagnosticRow id:String? operation:String? reason:String
'''

def result_struct(g,name,fields):
    # Null result properties have ordinary Optional semantics, unlike command patches.
    props={k:{} for k in fields};required=[k for k,v in fields.items() if not v.endswith('?')]
    g.struct(name,{'properties':props,'required':required},types={k:v.rstrip('?') for k,v in fields.items()},conformance='Codable, Equatable, Sendable'+(', Identifiable' if fields.get('id')=='String' else ''))
    # Decode nullable result fields with decodeIfPresent; preserve unknown fields as extra values.
    import re
    g.models[name]=re.sub(r'c.contains\(\.init\("(\w+)"\)\) \? try c.decode\((.*?).self, forKey: \.init\("\1"\)\) : nil',r'try c.decodeIfPresent(\2.self, forKey: .init("\1"))',g.models[name])

schemas=json.load(open(sys.argv[1]))
for domain,namespace in MODULES:
    m=next(m for m in schemas if m['namespace']==namespace)
    path=ROOT/'swift'/'Sources'/('Colophon'+domain+'Kit');path.mkdir(parents=True,exist_ok=True)
    g=Generator()
    commands=[]
    for op in m['operations']:
        if domain=='Notes' and op['name'] in ('addNote','editNote'):continue # preview compatibility aliases
        name=upper(op['name']);commands.append((op['name'],name))
        g.struct(name,op['inputSchema'],conformance=domain+'DomainCommand',statics=f'public static let kind = "{op["name"]}"')
    header='// Generated by scripts/generate-swift-domains.py; core validates bounds and references.\nimport Foundation\n@_exported import ColophonSession\n\n'
    protocols=f'public protocol {domain}DomainCommand: TypedDomainCommand {{}}\nextension {domain}DomainCommand {{ public static var namespace: String {{ "{namespace}" }} }}\n'
    (path/'Commands.swift').write_text(header+protocols+'\n'+'\n\n'.join(g.models.values())+'\n')
    g=Generator()
    for name,fields in RESULTS[domain].items():result_struct(g,name,fields)
    for line in COMMON.strip().splitlines():
        name,fields=line.split(' ',1);result_struct(g,name,dict(f.split(':',1) for f in fields.split()))
    (path/'Values.swift').write_text(header+'\n\n'.join(g.models.values())+'\n')
    g=Generator();queries=[]
    for query in m['queries']:
        wire=query['name']
        if wire not in QUERIES[domain]:continue
        public_name={'getEpisode':'Episode','getQueue':'Queue','getPosition':'Position'}.get(wire,upper(wire))+'Query'
        schema=query['inputSchema']; schema=json.loads(json.dumps(schema));schema['properties'].pop('offset',None)
        paged='cursor' in schema['properties']
        # Alias the filter model so clients need not refer to a command's nested type.
        overrides=None
        if domain=='Saved' and 'query' in schema['properties']:
            g.swift_type(schema['properties']['query'],'SavedViewFilter');overrides={'query':'SavedViewFilter'}
        g.struct(public_name,schema,conformance=domain+'DomainQuery'+(', PagedDomainQuery' if paged else ''),statics=f'public static let name = "{ {"getEpisode":"episode","getQueue":"queue","getPosition":"position"}.get(wire,wire)}"\npublic typealias Value = {QUERIES[domain][wire]}',extras=False,types=overrides)
        queries.append((wire,public_name))
    (path/'Queries.swift').write_text(header+f'public protocol {domain}DomainQuery: TypedDomainQuery {{}}\nextension {domain}DomainQuery {{ public static var namespace: String {{ "{namespace}" }} }}\n\n'+'\n\n'.join(g.models.values())+'\n')
    (path/(domain+'Store.swift')).write_text(f'''import Observation
import ColophonSession

/// Keep one store per session. Load from actions/tasks; render cached plain values.
@Observable @MainActor public final class {domain}Store {{
    private let cache: NamespaceStore<DomainQueryKey, any Sendable>
    public var revision: UInt64 {{ cache.revision }}
    public var state: NamespaceStore<DomainQueryKey, any Sendable>.State {{ cache.state }}
    public init(session: ColophonSession, maximumQueries: Int = 64) {{
        cache = NamespaceStore(session: session, namespace: "{namespace}", maximumQueries: maximumQueries,
                               load: {{ try await $0.evaluate(session: session) }})
    }}
    public func cached<Q: {domain}DomainQuery>(_ query: Q) -> DomainQueryResult<Q.Value>? {{
        guard let key = try? DomainQueryKey(query) else {{ return nil }}
        return cache.cached(key) as? DomainQueryResult<Q.Value>
    }}
    /// The last result for `query`, current or not: render it while `load` refreshes.
    public func latest<Q: {domain}DomainQuery>(_ query: Q) -> (value: DomainQueryResult<Q.Value>, current: Bool)? {{
        guard let key = try? DomainQueryKey(query), let entry = cache.latest(key),
              let typed = entry.value as? DomainQueryResult<Q.Value> else {{ return nil }}
        return (typed, entry.current)
    }}
    @discardableResult public func load<Q: {domain}DomainQuery>(_ query: Q) async throws -> DomainQueryResult<Q.Value> {{
        let result = try await cache.load(DomainQueryKey(query))
        guard let typed = result as? DomainQueryResult<Q.Value> else {{ throw SessionError.invalidCommand }}
        return typed
    }}
    public func close() {{ cache.close() }}
}}
''')
    # Test dispatch exercises the public typed encoders/decoders for every operation/query.
    test=['import Foundation','import Testing',f'import Colophon{domain}Kit','',f'enum {domain}TestDispatch {{','    static func command(kind: String, payload: Data) throws -> DomainCommand {','        let decoder = JSONDecoder()','        switch kind {']
    for wire,name in commands:test.append(f'        case "{wire}": return try decoder.decode(Colophon{domain}Kit.{name}.self, from: payload).domainCommand()')
    test+=['        default: throw SessionError.invalidCommand','        }','    }',f'    @MainActor static func query(name: String, arguments: Data, expected: Data?, store: {domain}Store) async throws {{','        let decoder = JSONDecoder()','        switch name {']
    for wire,name in queries:
        aliases=[wire]
        if wire in ['getEpisode','getQueue','getPosition']:aliases.append(wire[3].lower()+wire[4:])
        test += [f'        case {", ".join(json.dumps(v) for v in aliases)}:',f'            let query = try decoder.decode(Colophon{domain}Kit.{name}.self, from: arguments)', '            let actual = try await store.load(query)',f'            if let expected {{ let wanted = try decoder.decode(DomainQueryResult<Colophon{domain}Kit.{name}.Value>.self, from: expected); #expect(actual == wanted) }}','            let encoded = try JSONEncoder().encode(actual)',f'            let decoded = try decoder.decode(DomainQueryResult<Colophon{domain}Kit.{name}.Value>.self, from: encoded)','            #expect(actual == decoded)']
    test+=['        default: throw SessionError.invalidCommand','        }','    }','}']
    (ROOT/'swift'/'Tests'/'ColophonDomainKitTests'/(domain+'Dispatch.swift')).write_text('// Generated by scripts/generate-swift-domains.py.\n'+'\n'.join(test)+'\n')
