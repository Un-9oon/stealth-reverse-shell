from pathlib import Path
import argparse
import sys
sys.dont_write_bytecode=True
import re, json, html, math, zipfile
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Flowable, KeepTogether
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from pypdf import PdfReader

ROOT=Path(__file__).resolve().parents[1]
ap=argparse.ArgumentParser(); ap.add_argument('--output-dir',default=str(ROOT/'outputs')); args=ap.parse_args()
OUT=Path(args.output_dir).resolve(); OUT.mkdir(parents=True,exist_ok=True)
DIAG=OUT/'diagrams'; DIAG.mkdir(exist_ok=True)
NAVY='#142D45'; BLUE='#176B91'; PALE='#EDF4F7'; GRAY='#52616D'; ORANGE='#A75228'
styles=getSampleStyleSheet()
styles.add(ParagraphStyle(name='BodyF',fontName='Times-Roman',fontSize=11.5,leading=16,alignment=TA_JUSTIFY,spaceAfter=9))
styles.add(ParagraphStyle(name='H1F',fontName='Helvetica-Bold',fontSize=19,leading=24,textColor=colors.HexColor(NAVY),spaceAfter=17))
styles.add(ParagraphStyle(name='H2F',fontName='Helvetica-Bold',fontSize=12,leading=16,textColor=colors.HexColor(BLUE),spaceBefore=9,spaceAfter=7))
styles.add(ParagraphStyle(name='SmallF',fontName='Helvetica',fontSize=8.5,leading=12,spaceAfter=7))
styles.add(ParagraphStyle(name='CellF',fontName='Helvetica',fontSize=8.3,leading=11))
styles.add(ParagraphStyle(name='CaptionF',fontName='Helvetica',fontSize=9,leading=12,textColor=colors.HexColor(GRAY),spaceBefore=7,spaceAfter=12))
styles.add(ParagraphStyle(name='CoverF',fontName='Helvetica-Bold',fontSize=34,leading=40,textColor=colors.HexColor(NAVY),spaceAfter=18))
styles.add(ParagraphStyle(name='SubF',fontName='Helvetica',fontSize=17,leading=24,textColor=colors.HexColor(BLUE),spaceAfter=18))
W=453
pages=[]; figs=[]; tabs=[]; md=[]
def para(t,sty='BodyF'): return Paragraph(t,styles[sty])
def table(headers,rows,widths=None):
    hs=ParagraphStyle('TableHeadF',parent=styles['CellF'],textColor=colors.white,fontName='Helvetica-Bold')
    data=[[Paragraph(html.escape(str(x)),hs) for x in headers]]+[[para(html.escape(str(x)),'CellF') for x in row] for row in rows]
    t=Table(data,colWidths=widths or [W/len(headers)]*len(headers),repeatRows=1,hAlign='LEFT')
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor(NAVY)),('TEXTCOLOR',(0,0),(-1,0),colors.white),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),7),('RIGHTPADDING',(0,0),(-1,-1),7),('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.HexColor(PALE),colors.white]),('LINEBELOW',(0,0),(-1,0),0.6,colors.HexColor(BLUE)),('LINEBELOW',(0,1),(-1,-1),0.3,colors.HexColor('#D7E0E5'))]))
    return t

ROUTES={
 'figure-5-2':{('s','l'):[(310,170),(345,170)],('l','s'):[(345,140),(310,140)],('r','s'):[(200,255),(200,195)],('s','r'):[(255,195),(255,255)]},
 'figure-5-3':{('p4','p2'):[(171,100),(140,100),(140,305),(171,305)]},
 'figure-5-7':{('e','c'):[(300,17),(316,17),(316,157),(300,157)]},
 'figure-5-11':{('ctrl','lab'):[(68,210),(68,233),(385,233),(385,210)]},
 'figure-5-12':{('valid','failed'):[(164,285),(148,285),(148,60),(164,60)]}
}

class Diagram(Flowable):
    def __init__(self,key,title,nodes,edges,h=310,notes=None):
        Flowable.__init__(self); self.width=W; self.height=h; self.key=key; self.nodes=nodes; self.edges=edges; self.title=title; self.notes=notes or []
        self.svg()
    def route(self,a,b,n):
        if (a,b) in ROUTES.get(self.key,{}): return ROUTES[self.key][(a,b)]
        x,y,xx,yy=self.points(n[a],n[b])
        if self.key=='figure-5-5':
            if n[a][-1]=='actor':x=n[a][1]+n[a][3]/2+(11 if xx>x else -11);y=n[a][2]+n[a][4]/2+2
            if n[b][-1]=='actor':xx=n[b][1]+n[b][3]/2+(-11 if x<xx else 11);yy=n[b][2]+n[b][4]/2+2
        return [(x,y),(xx,yy)]
    def label_point(self,pts):
        segments=list(zip(pts,pts[1:]));p,q=max(segments,key=lambda pq:(pq[0][0]-pq[1][0])**2+(pq[0][1]-pq[1][1])**2)
        return (p[0]+q[0])/2,(p[1]+q[1])/2
    def svg(self):
        h=self.height; n={x[0]:x for x in self.nodes}; s=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{h}" viewBox="0 0 {W} {h}"><rect width="100%" height="100%" fill="white"/><defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="{BLUE}"/></marker></defs>']
        if self.key=='figure-5-5': s.append(f'<rect x="120" y="{h-325}" width="214" height="325" fill="none" stroke="{GRAY}"/><text x="227" y="{h-332}" text-anchor="middle" font-family="Arial" font-size="8">ERS AI Outcome Analysis</text>')
        for a,b,label,*opt in self.edges:
            pts=self.route(a,b,n)
            s.append('<polyline points="'+' '.join(f'{x},{h-y}' for x,y in pts)+f'" fill="none" stroke="{BLUE}" stroke-width="1.1" marker-end="url(#arrow)"/>')
            if label:
                mx,my=self.label_point(pts);my=h-my;sw=max(22,len(label)*4.4)
                s.append(f'<rect x="{mx-sw/2}" y="{my-9}" width="{sw}" height="12" fill="white"/><text x="{mx}" y="{my}" text-anchor="middle" font-family="Arial" font-size="8" fill="{GRAY}">{html.escape(label)}</text>')
        for _,x,y,w,hh,label,*kind in self.nodes:
            k=kind[0] if kind else 'box'
            if self.key=='figure-5-5' and k=='actor':
                cx=x+w/2; cy=h-(y+hh/2)
                s.append(f'<circle cx="{cx}" cy="{cy-12}" r="5" fill="white" stroke="{BLUE}"/><path d="M {cx} {cy-7} V {cy+7} M {cx-10} {cy-2} H {cx+10} M {cx} {cy+7} L {cx-9} {cy+17} M {cx} {cy+7} L {cx+9} {cy+17}" fill="none" stroke="{BLUE}"/><text x="{cx}" y="{cy+29}" text-anchor="middle" font-family="Arial" font-size="8">{html.escape(label)}</text>');continue
            fill=PALE if k!='actor' else '#FFF5ED'; rx=hh/2 if k=='process' else 4
            s.append(f'<rect x="{x}" y="{h-y-hh}" width="{w}" height="{hh}" rx="{rx}" fill="{fill}" stroke="{BLUE}"/>')
            lines=label.split('\n'); yy=h-(y+hh/2)+(len(lines)-1)*-5.7
            for i,line in enumerate(lines): s.append(f'<text x="{x+w/2}" y="{yy+i*11.4+3}" text-anchor="middle" font-family="Arial" font-size="8.4" fill="{NAVY}">{html.escape(line)}</text>')
            if k=='store': s.append(f'<line x1="{x+7}" y1="{h-y}" x2="{x+7}" y2="{h-y-hh}" stroke="{BLUE}"/>')
        for x,y,t in self.notes:s.append(f'<text x="{x}" y="{h-y}" font-family="Arial" font-size="8" fill="{GRAY}">{html.escape(t)}</text>')
        if self.key=='figure-5-5':
            import re as _re
            s=[_re.sub(r' marker-end="url\(#arrow\)"','',v) for v in s]
        s.append('</svg>'); (DIAG/(self.key+'.svg')).write_text('\n'.join(s),encoding='utf-8')
    def points(self,p,q):
        _,x,y,w,h,*_=p; _,xx,yy,ww,hh,*_=q; cx,cy=x+w/2,y+h/2; dx,dy=xx+ww/2-cx,yy+hh/2-cy
        if abs(dx)/(w or 1)>abs(dy)/(h or 1):return (x+w if dx>0 else x,cy,xx if dx>0 else xx+ww,yy+hh/2)
        return (cx,y+h if dy>0 else y,xx+ww/2,yy if dy>0 else yy+hh)
    def draw(self):
        c=self.canv; n={x[0]:x for x in self.nodes}
        if self.key=='figure-5-5':
            c.setStrokeColor(colors.HexColor(GRAY));c.rect(120,0,214,325,fill=0,stroke=1);c.setFont('Helvetica',8);c.drawCentredString(227,332,'ERS AI Outcome Analysis')
        for a,b,label,*opt in self.edges:
            pts=self.route(a,b,n);c.setStrokeColor(colors.HexColor(BLUE));c.setLineWidth(1)
            for (x1,y1),(x2,y2) in zip(pts,pts[1:]):c.line(x1,y1,x2,y2)
            (x1,y1),(x2,y2)=pts[-2:]
            angle=math.atan2(y2-y1,x2-x1); path=c.beginPath();path.moveTo(x2,y2);path.lineTo(x2-6*math.cos(angle-.45),y2-6*math.sin(angle-.45));path.lineTo(x2-6*math.cos(angle+.45),y2-6*math.sin(angle+.45));path.close();c.setFillColor(colors.HexColor(BLUE))
            if self.key!='figure-5-5':c.drawPath(path,fill=1,stroke=0)
            if label:
                c.setFont('Helvetica',7.5);tw=c.stringWidth(label,'Helvetica',7.5);mx,my=self.label_point(pts);c.setFillColor(colors.white);c.rect(mx-tw/2-3,my-2,tw+6,11,fill=1,stroke=0);c.setFillColor(colors.HexColor(GRAY));c.drawCentredString(mx,my+1,label)
        for _,x,y,w,h,label,*kind in self.nodes:
            k=kind[0] if kind else 'box'
            if self.key=='figure-5-5' and k=='actor':
                cx=x+w/2;cy=y+h/2;c.setStrokeColor(colors.HexColor(BLUE));c.circle(cx,cy+12,5,fill=0);c.line(cx,cy+7,cx,cy-7);c.line(cx-10,cy+2,cx+10,cy+2);c.line(cx,cy-7,cx-9,cy-17);c.line(cx,cy-7,cx+9,cy-17);c.setFillColor(colors.HexColor(NAVY));c.setFont('Helvetica',8);c.drawCentredString(cx,cy-29,label);continue
            c.setStrokeColor(colors.HexColor(BLUE));c.setFillColor(colors.HexColor('#FFF5ED' if k=='actor' else PALE));c.roundRect(x,y,w,h,h/2 if k=='process' else 4,fill=1,stroke=1)
            if k=='store':c.line(x+7,y,x+7,y+h)
            lines=label.split('\n');c.setFillColor(colors.HexColor(NAVY));c.setFont('Helvetica',8.4)
            for i,line in enumerate(lines): c.drawCentredString(x+w/2,y+h/2+(len(lines)-1)*5.7-i*11.4-3,line)
        c.setFont('Helvetica',8);c.setFillColor(colors.HexColor(GRAY))
        for x,y,t in self.notes:c.drawString(x,y,t)

def P(title,*blocks):
    pages.append((title,list(blocks)));return len(pages)
def H(t):return ('h',t)
def T(title,headers,rows,widths=None):return ('t',title,headers,rows,widths)
def F(num,title,nodes,edges,h=310,notes=None):return ('f',num,title,nodes,edges,h,notes)
def B(*items):return ('b',items)


ROUTES.update({'figure-5-3': {('lab','px'):[(343,355),(281,355)],('san','exp'):[(171,255),(147,255),(147,65),(171,65)]}, 'figure-5-7':{('e','c'):[(300,17),(316,17),(316,157),(300,157)]},'figure-5-11':{('px','lab'):[(68,210),(68,232),(385,232),(385,210)]},'figure-5-4':{('rej','out'):[(62,170),(62,30),(390,30),(390,65)]}})
P('Title page',('cover',))
P('Declaration and report status',
 'This report revises the existing ERS final-year-project report around the agreed single AI feature: session-outcome analysis. The Linux and Windows reverse-shell framework remains the existing experimental foundation. A proposed read-only assistant classifies the observed outcomes of predeclared harmless laboratory tasks; it does not select or execute commands or improve evasion.',
 H('Authorship and approval'),
 'Students must distinguish reused framework code from their own dataset, classifier, evaluation and reporting work. This document is a design and methodology revision, not a signed declaration of authorship, institutional approval or completed experiments. Acknowledgements and real signatures must be completed before submission.',
 T('Submission information',['Field','Status'],[['Project foundation','ERS Linux and ERS-W Windows'],['Department','Cyber Security, as stated in the original report'],['Academic session','2025-2026 in the original; confirm before submission'],['Students / registration IDs / university','Not supplied'],['Supervisor / approval signatures','Not supplied; unsigned'],['Revision / prepared','2.0 / 22 October 2026']],[170,283]),
 H('Document authority'),
 'This revision supersedes the original report\'s unsupported numerical stealth comparisons. Existing functionality is acknowledged at a high level; payload delivery, evasion and persistence procedures are not extended. New runtime analysis modules, training and experiments remain proposed. The institution\'s exact formatting template was not supplied.')
P('Abstract',
 'ERS is an existing cross-platform reverse-shell assessment framework with Rust implementations for Linux and Windows and Python-based listeners. This project proposes a single AI enhancement: evidence-grounded session-outcome classification in controlled laboratories. The assistant analyzes sanitized operator-side observations to estimate whether a predeclared harmless task completed with full output, executed with incomplete output, failed, or remains inconclusive. The existing framework remains the experimental tool; the model has no command-execution or traffic-control authority.',
 'The central problem is that connection establishment, endpoint execution and complete output delivery are different events. An interrupted session may provide insufficient evidence to infer the task outcome. The proposed method uses independently recorded endpoint outcomes as supervised targets and offline evaluation ground truth, while preventing those labels from entering the inference features. A bounded analytical pipeline normalizes observations, constructs task-linked windows, trains baseline classifiers and returns predictions with confidence and evidence references.',
 'Evaluation compares explicit rules, majority prediction, logistic regression and gradient-boosted trees using session- and machine-group holdouts. Primary measures include per-class precision and recall, macro-F1, false-success conclusions, calibration, abstention coverage and analysis overhead. Additional tests address missing events, concurrent sessions, schema mismatches and interrupted evidence writes. Expected outputs are a labeled lab dataset, one integrated outcome classifier, a reproducible benchmark and evidence-linked reports. Novelty and usefulness are hypotheses to validate; the revision claims no trained-model results, undetectability, universal detection resistance or production certification.',
 H('Keywords'),
 'Reverse shell; controlled adversary emulation; session-outcome classification; supervised learning; ground truth; incomplete observations; cross-platform evaluation.',
 H('Core idea'),
 'Retain ERS as the laboratory assessment tool and add one read-only AI assistant that predicts outcomes from sanitized observations, with independent evidence used to verify its predictions.')
P('Table of contents',('toc',))
P('List of figures tables and abbreviations',('lists',))

P('1. Introduction',
 H('1.1 Existing project'),
 'The repository contains ERS for Linux and ERS-W for Windows, primarily implemented in Rust, plus Python listeners and supporting automation [1]. The original framework establishes endpoint-to-operator sessions for authorized laboratory assessments. This report adds an observational research component rather than a new shell, delivery mechanism or autonomous operator.',
 H('1.2 Motivation'),
 'A listener can show that a connection exists without proving that a particular task ran or that all output arrived. Network interruption, incomplete records and ambiguous messages can produce unsupported success or failure conclusions. An assessment assistant is useful only if it improves interpretation beyond a well-designed rule baseline.',
 H('1.3 Current evidence'),
 'The student reports establishing a same-network reverse-shell session and capturing traffic on both endpoints. Those captures were not supplied for this revision and the experiment was not reproduced. This is a user-reported feasibility observation, not independently validated model performance or general stealth evidence.',
 H('1.4 Research question'),
 'Can a trained classifier infer controlled remote-assessment task outcomes from incomplete operator-side observations more accurately than explicit rules, while generalizing across held-out machines and Linux/Windows environments?',
 H('1.5 Single-feature boundary'),
 'The only proposed AI feature is outcome classification. Failure root-cause diagnosis, attack planning, payload generation, autonomous command selection, stealth optimization and cleanup prediction are excluded from the initial AI implementation.')
P('1. Problem statement and objectives',
 H('1.6 Problem statement'),
 'The framework\'s visible connection state and text output are not an independent record of endpoint execution. A task may execute while its response is lost, partially delivered or missing from the capture. Conversely, no visible output does not prove execution failure. The project needs a repeatable way to compare predicted outcomes with separately observed ground truth.',
 T('Table 1.1 Objectives and evidence',['ID','Objective','Required evidence'],[['O1','Retain the existing experimental framework','Baseline provenance and scoped synthetic-lab runs'],['O2','Define one outcome taxonomy','Documented labels, boundaries and ambiguous cases'],['O3','Train our own outcome classifier','Versioned data, training configuration and model'],['O4','Verify predictions independently','Separate endpoint records and label-review provenance'],['O5','Compare fairly against rules','Held-out groups, per-class scores and false-success rate'],['O6','Provide reproducible handover','Contracts, source mapping, milestones and checks']],[35,190,228]),
 H('1.7 Expected contribution'),
 'The candidate contribution is a cross-platform laboratory benchmark and evaluated outcome-classification assistant under incomplete observations. A new reverse shell or the presence of AI alone is not claimed as novelty. The exact gap needs a broader related-work review and measured evidence.')
P('2. Proposed solution and scope',
 H('2.1 Proposed workflow'),
 'After an authorized synthetic run, import sanitized listener observations into a separate analysis pipeline. Correlate them with lab-issued session and task identifiers, construct bounded task windows, apply a trained classifier and produce a structured outcome prediction. Offline evaluation joins frozen predictions to independent endpoint records.',
 H('2.2 Smallest useful implementation'),
 'Begin with offline post-session analysis. It minimizes coupling to the shell and makes datasets, labels and comparisons auditable. A later read-only listener dashboard may display completed predictions, but the model never sends instructions back to the agent or changes session behavior.',
 T('Table 2.1 Scope boundaries',['Included','Excluded from the proposed AI feature'],[['Outcome prediction and abstention','Command selection or execution'],['Sanitized task/session observations','Raw command text, credentials and sensitive output'],['Synthetic endpoint truth for evaluation','Oracle labels as live model input'],['Rules and student-trained models','Unrestricted LLM-generated operational actions'],['Repeated authorized lab experiments','External targets or unauthorized deployment']],[220,233]),
 H('2.3 Value to the two subjects'),
 'Penetration Testing contributes scoped adversary-emulation experiments, task verification and evidence reporting. Artificial Intelligence contributes labeled data, feature design, supervised training, uncertainty handling and generalization evaluation. The classifier supports assessment interpretation; it does not make the framework harder to detect.')

P('3. Literature review',
 H('3.1 Review approach'),
 'This is a focused narrative review checked on 22 October 2026, not an exhaustive systematic review. Sources include primary paper records, conference pages, official tool documentation and the source repository. Searches covered AI-assisted penetration testing, log analysis, session evidence and encrypted-traffic evaluation. Publication types and limits are stated in the references.',
 H('3.2 AI-assisted assessment'),
 'PentestGPT [2] studies LLM-assisted penetration testing and assessment context. AutoPentester [3] studies iterative tool-driven automation. These establish that AI integration and automated assessment are prior work. The proposed classifier has a narrower target: task outcome interpretation without planning or execution authority.',
 H('3.3 Log anomaly detection and diagnosis'),
 'LogBERT [4] learns normal log-sequence behavior and detects anomalies. An anomaly is not equivalent to execution failure or incomplete output. LogRCA [5] identifies candidate root-cause evidence from distributed-service logs. It establishes diagnostic learning as prior work, but the proposed project intentionally limits its output to outcome classes rather than causal explanations.',
 H('3.4 Evaluation quality'),
 'A recent encrypted-C2 measurement study [6] highlights leakage and ground-truth problems that can inflate performance claims. Its task is traffic detection rather than execution-outcome classification, but the evaluation lesson applies: independent grouping, label provenance and training-only preprocessing are essential.')
P('3. Research gap and contribution boundaries',
 T('Table 3.1 Literature comparison',['Work','Established focus','Proposed task distinction'],[['PentestGPT [2]','LLM assessment assistance','Outcome classification from fixed observations'],['AutoPentester [3]','Iterative assessment automation','Read-only analysis without action selection'],['LogBERT [4]','Log-sequence anomaly detection','Task-specific outcome labels'],['LogRCA [5]','Failure/root-cause evidence','Outcome only; causation not claimed'],['C2 evaluation study [6]','Leakage-controlled detection measurement','Execution/output ground truth at task level']],[104,167,182]),
 H('3.5 Candidate gap'),
 'The reviewed sources do not by themselves establish an independently verified benchmark for classifying ERS task outcomes under incomplete operator observations across Linux and Windows. This is a candidate domain-specific contribution inferred from their stated objectives, not proof that no related benchmark exists.',
 H('3.6 Necessary follow-up review'),
 'Before claiming novelty, examine remote-administration task tracking, distributed execution semantics, missing-data classification, selective prediction and agent-evaluation benchmarks. Official tool task-tracking capabilities must also be considered; session management already exists in mature frameworks.',
 H('3.7 Falsifiability'),
 'If explicit rules are equally accurate, retain that result. If observables cannot distinguish outcomes, report the information limit and abstain. Do not manufacture ambiguous labels or weaken baselines to justify AI. The useful contribution may be the benchmark and negative findings rather than a superior model.')
P('3. Existing tools comparison',
 T('Table 3.2 Tool positioning based on official sources',['Tool','Documented role','Relationship to this FYP'],[['Existing ERS / ERS-W [1]','Rust Linux/Windows agents with Python listeners','Experimental foundation; reviewed claims need verification'],['Sliver [7]','Cross-platform adversary-emulation framework','Relevant alternative foundation; no stealth ranking asserted'],['Metasploit sessions [8]','Session details, history and session operations','Shows that session management is existing functionality'],['Cobalt Strike [9]','Adversary simulation; documented task/output tracking','Task correlation itself cannot be claimed as new'],['Proposed ERS outcome assistant','One trained outcome classifier and independent evaluation','Value depends on measured benefit over explicit rules']],[104,167,182]),
 H('3.8 Comparison limits'),
 'This is a scope comparison, not a head-to-head performance benchmark. No tool was executed for this report and no price, stealth percentage, detection ranking or universal feature-absence claim is asserted. Public descriptions do not establish the absence of an independently verified outcome benchmark.',
 H('3.9 Positioning'),
 'The FYP should compete on clarity of task definition, label quality, reproducibility and honest uncertainty, not unsupported claims that it is more evasive than commercial or open-source tools.')

P('4. Requirements engineering',
 T('Table 4.1 Functional requirements',['ID','Requirement','Acceptance evidence'],[['FR01','Import only scoped synthetic-run records','Manifest and schema rejection tests'],['FR02','Normalize and sanitize before storage','Secret-canary and field-allowlist checks'],['FR03','Keep tasks and sessions correctly separated','Interleaved-record fixtures'],['FR04','Predict one outcome with confidence/status','Contract and known-fixture checks'],['FR05','Abstain on inadequate observations','Incomplete/corrupt input fixtures'],['FR06','Keep oracle labels inaccessible to inference','Feature and access-boundary audit'],['FR07','Export evidence-linked predictions','Valid IDs, model version and provenance'],['FR08','Reproduce training and evaluation','Frozen data/split/model manifests']],[42,218,193]),
 H('4.1 Stakeholders'),
 'The operator performs approved lab assessments. The researcher builds datasets and models. A supervisor approves scope and methodology. An examiner reviews reproducibility and original contributions. The inference service is an observer, not an additional operator.',
 H('4.2 Quality requirements'),
 'Bound input size and analysis resources; reject unknown fields and schema versions; record missing observations; protect redacted evidence; use immutable snapshots; recover committed analysis records after interruption; and make model unavailability explicit. Do not change the agent or transport to improve connectivity or stealth as part of this research feature.')

P('5. Architecture diagram',
 F('5.1','Existing assessment foundation with a read-only AI layer',[
 ('op',0,275,125,45,'Authorized lab operator','actor'),('li',164,275,125,45,'Existing Python listener\nObserved session output'),('ep',328,275,125,45,'Existing ERS lab endpoint\nLinux or Windows','actor'),('san',164,165,125,50,'Offline sanitizer\nMetadata allowlist'),('win',0,65,125,55,'Task-window builder\nBounded records'),('ai',164,65,125,55,'Student-trained model\nOne outcome head'),('db',328,65,125,55,'Prediction store\nEvidence references','store'),('ui',328,0,125,35,'Read-only report')],
 [('op','li','authorized interaction'),('li','ep','existing session'),('li','san','exported observations'),('san','win','redacted events'),('win','ai','task window'),('ai','db','prediction / abstain'),('db','ui','review')],h=340),
 H('5.1 Architectural separation'),
 'The upper path represents the existing framework at a high level. The lower path is the proposed research analysis pipeline. No reverse edge connects the AI to task execution. Offline analysis is the initial implementation; it requires no model running on the lab endpoint.',
 H('5.2 Independent truth'),
 'A separately administered endpoint recorder verifies harmless task completion and expected output. Its labels are visible to the dataset curator and evaluator only. They never enter the live inference feature set.')
P('5. Context DFD',
 F('5.2','Context DFD for session-outcome analysis',[
 ('o',0,135,110,50,'Lab operator','actor'),('s',145,120,165,75,'0. ERS outcome assistant\nRead-only analysis','process'),('l',345,135,108,50,'Existing lab records','actor'),('r',145,255,165,45,'Researcher / model curator','actor'),('e',145,10,165,45,'Examiner / evaluator','actor')],
 [('o','s','approved run manifest'),('l','s','observation export'),('r','s','pinned model'),('s','r','redacted dataset'),('s','e','predictions + report')],h=320),
 H('5.3 Data-flow conventions'),
 'The context process is 0; Level 1 contains 1.0-5.0; Level 2 decomposes prediction process 4.0. Rounded shapes are processes, tinted boxes are external entities and marked rectangles are stores. Arrows carry data, not instructions to the agent.',
 'The operator supplies approved run context. Existing laboratory records supply observations. The researcher supplies a trusted model and receives redacted data. The examiner/evaluator receives predictions for comparison with separately held endpoint truth.')
P('5. DFD Level 1',
 F('5.3','Level 1 analysis pipeline',[
 ('o',0,410,110,35,'Operator','actor'),('p1',0,330,110,50,'1.0 Validate manifest','process'),('d1',0,230,110,48,'D1 Run manifest','store'),('r',343,230,110,45,'Researcher','actor'),('px',171,330,110,50,'2.0 Import records','process'),('lab',343,330,110,50,'Existing lab records','actor'),('san',171,230,110,50,'3.0 Sanitize and\nbuild task windows','process'),('ai',171,130,110,50,'4.0 Classify outcome','process'),('model',343,130,110,50,'D2 Model registry','store'),('exp',171,40,110,50,'5.0 Store and export','process'),('d3',343,40,110,50,'D3 Evidence store','store'),('out',0,40,110,50,'Examiner / researcher','actor')],
 [('o','p1','scope + run'),('p1','d1','frozen manifest'),('p1','px','approved run'),('d1','px','constraints'),('lab','px','observations'),('px','san','typed records'),('san','ai','window'),('r','model','trained model'),('model','ai','pinned artifact'),('ai','exp','prediction'),('san','exp','redacted events'),('exp','d3','records'),('exp','out','report / dataset')],h=455),
 H('5.4 Boundary consistency'),
 'These preserve the context inputs and outputs. Independent endpoint labels are excluded from this inference diagram and joined later by the research evaluator. Import validation rejects files outside the approved synthetic-run manifest.')
P('5. DFD Level 2',
 F('5.4','Level 2 outcome classification',[
 ('input',0,275,125,45,'From 3.0\nSanitized task window','actor'),('a',164,275,125,45,'4.1 Validate schema\nand completeness','process'),('reg',328,275,125,45,'D2 Model registry','store'),('b',164,170,125,50,'4.2 Extract features\nand predict class','process'),('c',164,65,125,50,'4.3 Calibrate and\napply abstention','process'),('out',328,65,125,50,'To 5.0\nPrediction record','actor'),('rej',0,170,125,50,'Invalid / unavailable\nExplicit status','actor')],
 [('input','a','window'),('a','b','valid input'),('reg','b','trusted model'),('a','rej','reject'),('b','c','probabilities'),('c','out','prediction / abstain'),('rej','out','no prediction')],h=340),
 H('5.5 Prediction is not verification'),
 'The model returns a predicted outcome, confidence, evidence IDs and analysis status. The evaluator later records whether this matches independent endpoint truth. A high confidence score cannot establish that execution occurred.',
 'Unknown schema, missing model and corrupt input receive explicit non-prediction statuses. A disconnected or empty window is not automatically labeled as execution failure.')
P('5. Use case diagram',
 F('5.5','Use cases for the outcome assistant',[
 ('op',0,140,95,50,'Lab operator','actor'),('su',0,260,95,45,'Supervisor','actor'),('re',358,140,95,50,'Researcher','actor'),('ex',358,20,95,45,'Examiner','actor'),('u1',142,260,167,45,'UC01 Approve scoped run','process'),('u2',142,180,167,45,'UC02 Import observations','process'),('u3',142,100,167,45,'UC03 Review prediction','process'),('u4',142,20,167,45,'UC04 Train and evaluate','process')],
 [('su','u1',''),('op','u2',''),('op','u3',''),('re','u4',''),('u3','ex',''),('u4','ex','')],h=350),
 T('Table 5.1 Use-case outcomes',['Case','Precondition','Result'],[['UC01','Lab approval and manifest','Frozen scope or rejection'],['UC02','Approved synthetic records','Redacted windows or invalid-input status'],['UC03','Stored prediction/evidence','Human review, not automatic execution'],['UC04','Dataset, oracle and grouped splits','Model and measured evaluation']],[44,188,221]),
 'All uses are analysis and research functions. Operator actions in the original framework remain outside AI authority.')
P('5. Misuse case diagram',
 F('5.6','Misuse cases and controls',[
 ('bad',0,150,100,60,'Untrusted input /\nmisconfiguration','actor'),('m1',137,265,150,43,'MC01 Execute model text','process'),('m2',137,180,150,43,'MC02 Export secrets','process'),('m3',137,95,150,43,'MC03 Leak oracle labels','process'),('m4',137,10,150,43,'MC04 Present guess as fact','process'),('c1',330,265,123,43,'Read-only interface'),('c2',330,180,123,43,'Allowlist + canaries'),('c3',330,95,123,43,'Separate oracle store'),('c4',330,10,123,43,'Prediction / truth split')],
 [('bad','m1','attempt'),('bad','m2','attempt'),('bad','m3','attempt'),('bad','m4','attempt'),('m1','c1','mitigated by'),('m2','c2','mitigated by'),('m3','c3','mitigated by'),('m4','c4','mitigated by')],h=325),
 H('5.6 Misuse acceptance checks'),
 'Reject arbitrary command fields in prediction requests. Scan synthetic secret canaries before storage and export. Audit that inference cannot access endpoint truth. Display predictions, confidence and independent verification as distinct fields. The assistant never sends generated text to a listener or endpoint.')
P('5. Activity and sequence diagrams',
 F('5.7','Post-session outcome analysis activity',[
 ('a',150,280,150,35,'Validate run manifest'),('b',150,210,150,35,'Import permitted records'),('c',150,140,150,35,'Sanitize and correlate'),('d',150,70,150,35,'Close task window'),('e',150,0,150,35,'Classify and persist'),('stop',0,140,110,35,'Ambiguous: mark unknown'),('done',343,0,110,35,'Operator review')],
 [('a','b','valid'),('b','c','typed records'),('c','d','correlated'),('c','stop','ambiguous'),('d','e','bounded input'),('e','done','prediction'),('e','c','next task')],h=325),
 H('5.7 Processing order'),
 'Import, sanitize, correlate, predict and persist without modifying the original assessment. Do not combine tasks based only on similar timestamps. Ambiguous records remain explicitly unassigned or inconclusive. Figure 5.8 on the next page details the analysis interactions.')
P('5. Analysis sequence',('sequence',),
 H('5.8 Independent evaluation'),
 'The model sees only the sanitized operator-observation window. Predictions are frozen before an evaluator joins endpoint truth. Offline joins use lab-issued identifiers and reviewed provenance; the join is not a runtime model dependency.',
 'If the analysis service is unavailable, the importer records UNAVAILABLE and can be rerun later. No reconnect, execution retry or agent change is triggered by the assistant.')
P('5. Data model and deployment',
 F('5.9','Evidence schema with isolated research labels',[
 ('run',0,245,136,72,'Run\nPK run_id\nmanifest_hash, platform'),('task',158,245,136,72,'TaskWindow\nPK window_id; FK run_id\nsession_id, task_id'),('model',316,245,137,72,'ModelVersion\nPK model_id\nartifact_hash, schema'),('event',0,105,136,82,'Observation\nPK event_id; FK window_id\nkind, timing, completeness'),('pred',158,105,136,82,'Prediction\nPK prediction_id\nFK window_id, model_id\nclass, confidence, status'),('truth',316,105,137,82,'OracleLabel [research]\nPK label_id; FK window_id\ntruth, provenance'),('link',158,0,137,60,'PredictionEvidence\nPK/FK prediction_id\nPK/FK event_id')],
 [('run','task','1 : many'),('model','pred','1 : many'),('task','event','1 : many'),('task','pred','1 : many'),('task','truth','1 : 0..many'),('pred','link','1 : many'),('event','link','1 : many')],h=335),
 H('5.9 Storage and deployment'),
 'Deploy the initial assistant on the operator workstation as an offline tool or isolated local service. The model has no endpoint route, listener-control credentials or oracle access. Use a transactional redacted evidence store and a separately permissioned research-label store. Foreign keys protect evidence references.')

P('6. Methodology and label definitions',
 H('6.1 Unit of analysis'),
 'One prediction concerns one predeclared harmless task within a laboratory session. The model is called a session-outcome assistant because it analyzes session observations, but the evaluated unit is the task episode. A connection may contain multiple tasks; do not infer that all succeeded from one successful task.',
 T('Table 6.1 Outcome taxonomy',['Class','Independent definition'],[['EXECUTION_COMPLETE','Endpoint completion and expected full output receipt independently verified'],['OUTPUT_INCOMPLETE','Endpoint execution verified; expected output receipt demonstrably partial or absent'],['EXECUTION_FAILED','Trusted fixture records explicit execution failure; not merely missing output'],['INCONCLUSIVE','Available independent records do not establish one of the other outcomes']],[155,298]),
 'Prediction status is separate: PREDICTED, ABSTAINED, UNAVAILABLE or INVALID_INPUT. INCONCLUSIVE describes the label; ABSTAINED describes a model decision to withhold a prediction.',
 H('6.2 Label authority'),
 'The endpoint recorder and synthetic fixture define actual completion and expected output properties. A missing listener response alone cannot label failure. A partial endpoint recorder cannot establish a complete negative; mark the case inconclusive. Keep labeling criteria fixed and version corrections.')
P('6. Dataset and experimental conditions',
 H('6.3 Controlled collection'),
 'Use isolated Linux and Windows virtual machines, synthetic identities and preapproved harmless fixtures with known expected results. Collect normal completion, incomplete observations, explicit fixture failure and ambiguous cases. Record both actual outcome and observation availability separately.',
 T('Table 6.2 Dataset design',['Dimension','Plan','Control'],[['Platforms','Linux and Windows lab VMs','Record exact image and software versions'],['Grouping','Run, machine, session, task and capture period','Keep related records in one split'],['Conditions','Normal and controlled interrupted observations','No evasion optimization or autonomous reactions'],['Pilot size','Estimate after initial collection','Do not claim a fixed count guarantees power'],['Truth review','Independent recorder plus reviewed sample','Preserve disagreements and unknowns']],[95,180,178]),
 H('6.4 Data minimization'),
 'Export normalized metadata only. Exclude command strings, credentials, environment dumps, file contents and raw output. Optional size, timing, event-count and completeness summaries must be derived without saving sensitive values. Do not hash secret content as an identity shortcut.',
 H('6.5 Observability limit'),
 'If two true outcomes produce identical allowed observations, no classifier can reliably distinguish those cases from those inputs alone. Report that limitation, evaluate abstention and avoid claiming that a model reconstructs hidden execution with certainty.')
P('6. Features and student training',
 T('Table 6.3 Proposed feature groups',['Group','Examples','Constraint'],[['Observed sequence','Connection seen; output chunk seen; close event','No synthetic oracle completion event'],['Timing','Relative intervals; observation duration','No future records; bound values'],['Completeness','Missing-log flag; chunk count; truncation flag','Flag source must be an allowed observation'],['Output metadata','Size bucket and observed terminal marker availability','No raw output or fixture-answer fingerprints'],['Identifiers','Opaque run/session/task/window IDs','Grouping only, never predictive inputs']],[103,190,160]),
 H('6.6 Baselines and models'),
 'Implement explicit rules and a majority baseline before training. Fit logistic regression and gradient-boosted trees on the same allowed window features. The students train and version the selected model. A large language model or external API is not required. A sequence model is optional future work, not part of the initial single-feature commitment.',
 H('6.7 Selection and calibration'),
 'Fit preprocessing on training groups only. Tune hyperparameters, class weighting, confidence calibration and abstention thresholds on validation groups only. Freeze the final artifact before testing. Rules must receive the same informative observations as the model; do not deliberately weaken them.')
P('6. Training pipeline',
 F('6.1','Supervised outcome training and held-out evaluation',[
 ('gen',0,265,130,50,'Synthetic task episodes\nSeparate endpoint truth'),('obs',160,265,130,50,'Sanitized observations\nVersioned target labels'),('split',320,265,130,50,'Grouped split manifest\nHold out machines'),('train',0,135,130,60,'Train rules baseline\nand simple classifiers'),('val',160,135,130,60,'Validation: select model\nand abstention threshold'),('test',320,135,130,60,'Frozen holdout\nCompare with oracle'),('reg',160,15,130,60,'Registry and report\nData/code/model hashes')],
 [('gen','obs','offline correlation'),('obs','split','reviewed records'),('split','train','training groups'),('train','val','candidate model'),('val','test','frozen choice'),('test','reg','metrics + limits')],h=330),
 H('6.8 Split protocol'),
 'All tasks from one session and all near-duplicate fixture runs belong to the same split. Hold out machines and collection periods. Report Linux and Windows separately. Cross-OS transfer is an additional experiment and must not be implied by a mixed-platform random split.',
 'When choosing model designs after inspecting test folds, obtain a new untouched holdout for a final claim. Dataset size, prevalence and exclusions must be reported at the independent episode/group level.')

P('7. Technical design and integration',
 T('Table 7.1 Existing versus proposed components',['Component','Existing foundation','Proposed analytical work'],[['ERS/src/main.rs','Linux Rust agent','No new execution/evasion behavior in this feature'],['ERS-W/src/main.rs','Windows Rust agent','No new payload or persistence behavior'],['ERS/listener.py and ERS-W/listener.py','Operator-side session interfaces','Use permitted exported records; inspect actual schemas'],['analysis/','Not established as existing','Importer, sanitizer, windows, prediction and reporting'],['ml/ and evaluation/','Proposed','Training, split audit and metric calculation'],['lab/','Proposed research fixtures','Independent truth and resettable benign scenarios']],[139,145,169]),
 H('7.1 Integration approach'),
 'Start as post-session analysis of exported records; do not rewrite agent transport or dispatch. Inspect the actual pinned checkout before relying on existing log fields. If records do not support task correlation, record that as a feasibility limitation instead of fabricating certainty.',
 H('7.2 Input/output contract'),
 'Input: schema version, opaque run/session/task/window identifiers, ordered sanitized observations and completeness flags. Output: model version, predicted class, calibrated confidence or null, analysis status, abstention reason and evidence event IDs. Reject arbitrary instructions and unknown fields.')
P('7. Reliability and privacy of the assistant',
 T('Table 7.2 Analysis reliability checks',['Concern','Required behavior','Test evidence'],[['Resource limits','Bound input, window length and workers','Oversized import and saturation fixtures'],['Correlation','Never join different tasks silently','Interleaved and duplicate-ID fixtures'],['Privacy','Allowlist before persistence','Seeded-secret scan'],['Model outage','UNAVAILABLE without agent changes','Unavailable-service fixture'],['Storage','Recover committed redacted records','Interrupted-write recovery'],['Evidence integrity','Every reference exists and matches task','Foreign-key and report checks'],['Oracle leakage','No truth access during inference','Access and feature audit']],[96,203,154]),
 H('7.3 Proposed engineering targets'),
 'The first acceptance target is zero seeded-secret leakage and zero cross-task evidence joins in defined negative tests. A provisional local p95 analysis target is 250 ms per closed window on disclosed hardware. Freeze final bounds after the pilot; these are design targets, not achieved results.',
 'Offline analysis must not affect agent or listener availability. Protect synthetic records with appropriate file permissions and retention. Model errors must remain visible. Reprocessing creates a new model-versioned prediction rather than overwriting historical truth.')

P('8. Evaluation methodology',
 H('8.1 Main comparisons'),
 'Compare explicit rules, majority prediction, logistic regression and gradient-boosted trees on identical independent test episodes. Freeze the observation format and label taxonomy. Evaluate complete observations and missing-observation subsets separately. An ambiguous case is not evidence that the model is defective if the required information is absent; its uncertainty behavior must be measured.',
 T('Table 8.1 Metrics',['Measure','Definition / purpose'],[['Per-class precision and recall','Evaluate every outcome class separately'],['Macro-F1','Summarize performance without majority dominance'],['False-success rate','Incorrect EXECUTION_COMPLETE predictions among non-complete episodes'],['False-discovery among success claims','Incorrect complete predictions / all complete predictions'],['Risk versus coverage','Error among accepted predictions versus abstention rate'],['Calibration','Check whether confidence reflects observed correctness'],['Analysis overhead','Latency, CPU/RAM and record-processing throughput']],[158,295]),
 H('8.2 Statistical analysis'),
 'Use paired comparisons and confidence intervals resampling independent sessions or scenario groups, not individual correlated events. Determine sample size from pilot variability. Report missing data, unknown labels, failed runs and predeclared exclusions. Do not claim universal accuracy from a small same-network demonstration.')
P('8. Planned results and limitations',
 T('Table 8.2 Results template not measured',['Approach','Macro-F1','False-success rate','Coverage'],[['Explicit rules','Not measured','Not measured','Not measured'],['Majority baseline','Not measured','Not measured','Not measured'],['Logistic regression','Not measured','Not measured','Not measured'],['Gradient-boosted trees','Not measured','Not measured','Not measured']],[133,96,128,96]),
 H('8.3 Evidence status'),
 'No new model, dataset or outcome-classification evaluation was executed for this report revision. The earlier same-network experiment is user-reported and its captures were not reviewed here. Original stealth percentages and comparative rankings lack reproduced supporting evidence and are not adopted as results.',
 H('8.4 Limitations'),
 'Synthetic tasks may not represent complex assessments. Limited machines constrain external validity. Labels can be wrong if the endpoint recorder fails. Platform-specific event patterns can create shortcuts. Explicit rules may match or outperform ML. Packet captures cannot establish hidden execution semantics alone.',
 H('8.5 Interpreting a negative result'),
 'If the model provides no improvement, report the benchmark and information limits. If it is overconfident under missing observations, document the failure. The objective is reliable assessment evidence, not an obligatory claim that AI outperforms every alternative.')

P('9. Market value and feasibility',
 H('9.1 Intended value'),
 'Potential users include university security labs, penetration-testing instructors and internal assessment teams needing reproducible evidence review. The value hypothesis is fewer unsupported success claims, clearer student assessment and consistent Linux/Windows reporting. These benefits have not yet been validated with customers.',
 T('Table 9.1 Positioning and validation',['Aspect','Proposed position','How to validate'],[['Existing tools','Complement mature session interfaces','Review documented task tracking and avoid duplicate claims'],['Educational use','Visible predictions versus ground truth','Approved synthetic exercise and instructor review'],['Operational usefulness','Read-only post-session evidence assistant','Measure interpretation errors and review effort'],['Commercial readiness','Research prototype initially','No revenue, market size or certification assumed']],[100,183,170]),
 H('9.2 Resources and cost'),
 'A local CPU workstation and isolated Linux/Windows VMs are the initial plan. Small tabular models do not require an external LLM API or dedicated GPU. Record actual hardware, licensing, annotation time and compute cost. No unsupported product-pricing comparisons are included.',
 H('9.3 Practical scope'),
 'Deliver one reliable analytical feature before considering dashboards or natural-language explanations. The proposed tool is not positioned as a replacement for mature adversary-emulation frameworks.')
P('10. Project plan and risk register',('gantt',),
 T('Table 10.1 Milestones',['Weeks','Deliverable','Exit criterion'],[['1-2','Scope, review and taxonomy','Supervisor-reviewed question and labels'],['3-4','Synthetic fixtures and oracle','Verified complete/failure/unknown examples'],['5-6','Sanitized dataset and rules','Correlation and split audit'],['7-8','Training and local analysis','Versioned classifier and explicit abstention'],['9-10','Held-out evaluation','Metrics, limitations and privacy checks'],['11-12','Report and handover','Rebuildable artifacts and documented demo']],[46,170,237]),
 H('10.1 Principal risks'),
 'The main risks are insufficient observable information, oracle mistakes, shortcut learning, cross-task joins, insufficient sample size and no improvement over rules. Mitigate with reviewed truth records, group splits, privacy allowlists and a pilot-first plan. Do not expand into new offensive capabilities to compensate for weak research results.')
P('11. Conclusion and future work',
 H('11.1 Conclusion'),
 'The revised project keeps the existing ERS framework as an authorized laboratory assessment foundation and adds one student-trained outcome-classification assistant. The main research task is to distinguish supported task outcomes under incomplete observations while maintaining independent ground truth and honest uncertainty.',
 'The expected FYP contributions are a documented taxonomy, redacted dataset, baseline models, one integrated classifier and reproducible evaluation. The study does not claim a new reverse-shell concept, validated stealth superiority, global novelty or completed model performance.',
 H('11.2 Future work after the initial feature'),
 B('Extend the benchmark to additional independent lab machines and capture periods.', 'Investigate small sequence models if event ordering adds measured value.', 'Study transfer between Linux and Windows without platform-identity shortcuts.', 'Improve uncertainty calibration and explicitly characterize observational equivalence.', 'Add evidence-constrained natural-language summaries as a presentation layer.', 'Evaluate read-only analyst usability under institutional approval.'),
 H('11.3 Final claim criteria'),
 'A novelty claim requires a broader literature comparison and a clearly differentiated result or artifact. A usefulness claim requires fair comparisons with strong rules. A robustness claim applies only to measured analysis conditions. The original framework and proposed assistant must remain distinguishable in the final demonstration.')

P('Appendix A Implementation handover',
 H('A.1 Scope for another developer or AI'),
 'Implement session-outcome analysis only. Keep ERS and ERS-W as the existing experimental foundation. Do not substitute PhantomGate, authentication-flow diagnosis, autonomous next-test selection, stealth optimization or payload generation. Begin with offline records, explicit rules and independently verified synthetic fixtures.',
 H('A.2 First implementation increments'),
 B('Inspect the actual checkout, repository instructions and available supported tests; record the baseline commit.', 'Define allowed observation fields and one task-window schema; validate before persistence.', 'Create independently labeled harmless lab episodes and a correlation/label-review procedure.', 'Implement a rules baseline and an evidence-linked report before model training.', 'Train simple classifiers on frozen groups and evaluate against the same rules.', 'Integrate the selected read-only model and record actual validation evidence.'),
 H('A.3 Definition of done'),
 'One complete end-to-end dataset/training/evaluation run with independent labels; no forbidden fields in exports; no cross-task joins; explicit abstention and unavailable statuses; reproducible splits and model provenance; per-class results and false-success analysis; source/PDF consistency. This is an acceptance checklist, not a statement of completed implementation.',
 H('A.4 Before academic submission'),
 'Confirm the university template and academic session; complete names and signatures; add actual acknowledgements; identify student contributions and assistance; replace planned results with measured evidence; verify all sources and inspect the rendered PDF.')

refs=[
('[1]','Un-9oon/stealth-reverse-shell. Existing ERS and ERS-W framework and original FYP report. Baseline commit 20e0518de1bb31a866212e73b1882c4db5514772. Software artifact.','https://github.com/Un-9oon/stealth-reverse-shell/tree/20e0518de1bb31a866212e73b1882c4db5514772'),
('[2]','G. Deng et al. PentestGPT: Evaluating and Harnessing Large Language Models for Automated Penetration Testing. USENIX Security, pp. 847-864, 2024.','https://www.usenix.org/conference/usenixsecurity24/presentation/deng'),
('[3]','Y. Ginige, A. Niroshan, S. Jain, and S. Seneviratne. AutoPentester: An LLM Agent-based Framework for Automated Pentesting. arXiv:2510.05605, 2025; author record lists IEEE TrustCom 2025.','https://arxiv.org/abs/2510.05605'),
('[4]','H. Guo, S. Yuan, and X. Wu. LogBERT: Log Anomaly Detection via BERT. arXiv:2103.04475, 2021. Author manuscript.','https://arxiv.org/abs/2103.04475'),
('[5]','T. Wittkopp, P. Wiesner, and O. Kao. LogRCA: Log-based Root Cause Analysis for Distributed Services. arXiv:2405.13599, 2024; author record lists Euro-Par 2024 acceptance.','https://arxiv.org/abs/2405.13599'),
('[6]','H.-H. Nguyen-Huu, V.-T. Phan, and K. Nguyen-An. Multi-View Fusion for Encrypted C2 Detection: A Leakage-Controlled Measurement Study of Evaluation Pitfalls. arXiv:2609.27311, 2026. Author manuscript.','https://arxiv.org/abs/2609.27311'),
('[7]','Bishop Fox. Sliver adversary-emulation framework. Official software repository.','https://github.com/BishopFox/sliver'),
('[8]','Rapid7. Manage Your Meterpreter Session. Official Metasploit documentation.','https://docs.rapid7.com/metasploit/manage-meterpreter-and-shell-sessions/'),
('[9]','Fortra. Cobalt Strike Features. Official product documentation. Tool capabilities are descriptions, not independent comparative results.','https://www.cobaltstrike.com/product/features'),
('[10]','K. Scarfone, M. Souppaya, A. Cody, and A. Orebaugh. Technical Guide to Information Security Testing and Assessment. NIST SP 800-115, 2008. Guidance.','https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf')]
P('References',*['%s %s<br/><link href="%s" color="%s">%s</link>'%(i,html.escape(t),u,BLUE,u) for i,t,u in refs[:5]],'Sources checked on 22 October 2026. The literature review is focused and does not establish global uniqueness.')
P('References continued',*['%s %s<br/><link href="%s" color="%s">%s</link>'%(i,html.escape(t),u,BLUE,u) for i,t,u in refs[5:]],
 H('Assessment governance'),
 'NIST SP 800-115 [10] informs scope, authorization, evidence analysis and reporting. It does not certify this project. Use only approved laboratory assets and document the actual observation and labeling boundaries.')

class Sequence(Flowable):
    def __init__(self):
        Flowable.__init__(self);self.width=W;self.height=360
        xs=[40,135,230,325,420];names=['Operator','Importer','Classifier','Evidence','Evaluator']
        s=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="360"><rect width="100%" height="100%" fill="white"/>']
        for x,name in zip(xs,names):s.extend([f'<rect x="{x-38}" y="15" width="76" height="30" rx="3" fill="{PALE}" stroke="{BLUE}"/>',f'<text x="{x}" y="33" text-anchor="middle" font-family="Arial" font-size="8">{name}</text>',f'<line x1="{x}" y1="50" x2="{x}" y2="350" stroke="{BLUE}" stroke-dasharray="3 3"/>'])
        msgs=[(0,1,'Approved observation export'),(1,2,'Sanitized task window'),(2,1,'Outcome or abstention'),(1,3,'Freeze prediction + evidence'),(3,4,'Prediction snapshot'),(4,3,'Separate verified label'),(4,0,'Comparison report')]
        for i,(a,b,t) in enumerate(msgs):
            y=73+i*30;sgn=1 if xs[b]>xs[a] else -1
            s.extend([f'<path d="M {xs[a]} {y} H {xs[b]} M {xs[b]-sgn*5} {y-3} L {xs[b]} {y} L {xs[b]-sgn*5} {y+3}" fill="none" stroke="{BLUE}"/>',f'<text x="{(xs[a]+xs[b])/2}" y="{y-6}" text-anchor="middle" font-family="Arial" font-size="7.5">{html.escape(t)}</text>'])
        s.append('</svg>');(DIAG/'figure-5-8.svg').write_text('\n'.join(s),encoding='utf-8')
    def draw(self):
        c=self.canv;xs=[40,135,230,325,420];names=['Operator','Importer','Classifier','Evidence','Evaluator']
        for x,name in zip(xs,names):
            c.setFillColor(colors.HexColor(PALE));c.setStrokeColor(colors.HexColor(BLUE));c.roundRect(x-38,315,76,30,3,fill=1);c.setFillColor(colors.HexColor(NAVY));c.setFont('Helvetica-Bold',8);c.drawCentredString(x,327,name);c.setDash(3,3);c.line(x,310,x,10);c.setDash()
        msgs=[(0,1,'Approved observation export'),(1,2,'Sanitized task window'),(2,1,'Outcome or abstention'),(1,3,'Freeze prediction + evidence'),(3,4,'Prediction snapshot'),(4,3,'Separate verified label'),(4,0,'Comparison report')]
        for i,(a,b,t) in enumerate(msgs):
            y=287-i*30;c.setStrokeColor(colors.HexColor(BLUE));c.line(xs[a],y,xs[b],y);sgn=1 if xs[b]>xs[a] else -1;c.line(xs[b],y,xs[b]-sgn*5,y+3);c.line(xs[b],y,xs[b]-sgn*5,y-3);c.setFont('Helvetica',7.5);c.setFillColor(colors.HexColor(NAVY));c.drawCentredString((xs[a]+xs[b])/2,y+6,t)

class Gantt(Flowable):
    def __init__(self):
        Flowable.__init__(self);self.width=W;self.height=185
        s=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="185"><rect width="100%" height="100%" fill="white"/>']
        for w in range(12):s.append(f'<text x="{125+w*26+13}" y="15" text-anchor="middle" font-family="Arial" font-size="8">{w+1}</text>')
        for i,label in enumerate(['Scope + literature','Fixtures + oracle','Dataset + rules','Train + analyze','Evaluate + verify','Report + handover']):
            y=26+i*25;s.append(f'<text x="0" y="{y+13}" font-family="Arial" font-size="8">{label}</text>')
            for w in range(12):s.append(f'<rect x="{125+w*26}" y="{y}" width="26" height="19" fill="white" stroke="#D7E0E5"/>')
            s.append(f'<rect x="{125+i*52}" y="{y+1}" width="52" height="17" fill="{BLUE}"/>')
        s.append('</svg>');(DIAG/'figure-10-1.svg').write_text('\n'.join(s),encoding='utf-8')
    def draw(self):
        c=self.canv;labels=['Scope + literature','Fixtures + oracle','Dataset + rules','Train + analyze','Evaluate + verify','Report + handover'];left=125;cw=26
        c.setFont('Helvetica',8)
        for w in range(12):c.drawCentredString(left+w*cw+cw/2,170,str(w+1))
        for i,label in enumerate(labels):
            y=140-i*25;c.setFillColor(colors.HexColor(NAVY));c.drawString(0,y+6,label)
            for w in range(12):c.setStrokeColor(colors.HexColor('#D7E0E5'));c.rect(left+w*cw,y,cw,19,stroke=1,fill=0)
            c.setFillColor(colors.HexColor(BLUE));c.rect(left+i*2*cw,y+1,2*cw,17,stroke=0,fill=1)

def roman(n):
    vals=[(10,'x'),(9,'ix'),(5,'v'),(4,'iv'),(1,'i')];s=''
    for v,t in vals:
        while n>=v:s+=t;n-=v
    return s
def page_label(i):return '' if i==1 else roman(i-1) if i<=5 else str(i-5)
for pi,(title,blocks) in enumerate(pages,1):
    for b in blocks:
        if isinstance(b,tuple) and b[0]=='f':figs.append((b[1],b[2],pi))
        elif isinstance(b,tuple) and b[0]=='t':tabs.append((b[1],pi))
        elif isinstance(b,tuple) and b[0]=='sequence':figs.append(('5.8','Assessment interaction sequence',pi))
        elif isinstance(b,tuple) and b[0]=='gantt':figs.append(('10.1','Proposed twelve-week schedule',pi))

story=[]
def add_md_table(headers,rows):
    md.append('| '+' | '.join(headers)+' |\n| '+' | '.join(['---']*len(headers))+' |')
    for row in rows:md.append('| '+' | '.join(str(x).replace('|','/') for x in row)+' |')
for pi,(title,blocks) in enumerate(pages,1):
    if pi>1:story.append(PageBreak())
    md.append('\n# '+title+'\n')
    if pi!=1:story.append(para(title,'H1F'))
    for block in blocks:
        if isinstance(block,str):story.append(para(block));md.append(re.sub('<[^>]+>','',html.unescape(block))+'\n');continue
        kind=block[0]
        if kind=='h':story.append(para(block[1],'H2F'));md.append('## '+block[1]+'\n')
        elif kind=='b':
            for x in block[1]:story.append(para('&#8226; '+x));md.append('- '+x)
        elif kind=='t':
            _,cap,heads,rows,widths=block;story.extend([para(cap,'CaptionF'),table(heads,rows,widths),Spacer(1,12)]);md.append('**'+cap+'**');add_md_table(heads,rows)
        elif kind=='f':
            _,num,cap,nodes,edges,height,notes=block;key='figure-'+num.replace('.','-');story.extend([Diagram(key,cap,nodes,edges,height,notes),para('Figure '+num+' - '+cap+'. Proposed design.','CaptionF')]);md.append(f'![Figure {num} - {cap}](diagrams/{key}.svg)\n')
        elif kind=='cover':
            story.extend([Spacer(1,40),para('FINAL YEAR PROJECT | REVISED DESIGN REPORT','SmallF'),Spacer(1,35),para('ERS AI Outcome Analysis','CoverF'),para('Cross Platform Reverse Shell Assessment with AI Session Outcome Analysis','SubF'),Spacer(1,25),para('Penetration Testing + Artificial Intelligence','H2F'),Spacer(1,20),para('Existing foundation: ERS Linux and ERS-W Windows. Proposed AI feature: one read-only classifier for verified laboratory task outcomes.'),Spacer(1,65),table(['Submission information','Status'],[['Student(s) / registration ID(s)','Not supplied'],['University / department / degree','Not supplied'],['Supervisor / academic session','Not supplied'],['Revision / prepared','2.0 - Revised FYP proposal / 22 October 2026']],[210,243]),Spacer(1,28),para('Existing framework acknowledged. AI classification and evaluation remain proposed. No trained-model results or stealth scores are claimed.','SmallF')]);md.extend(['**Cross Platform Reverse Shell Assessment with AI Session Outcome Analysis**','Revision 2.0 - Revised FYP proposal. Prepared 22 October 2026.','Team, university, department, degree, supervisor and academic session: not supplied.'])
        elif kind=='toc':
            rows=[]
            for j,(tt,_) in enumerate(pages,1):
                if j in [2,3,5] or (j>=6 and (j==6 or tt.split(' - ')[0]!=pages[j-2][0].split(' - ')[0])):
                    # Collapse chapter continuations to chapter starts.
                    if j>=6 and not (re.match(r'^\d+\. ',tt) and (j==6 or tt.split('.')[0]!=pages[j-2][0].split('.')[0])) and not tt.startswith(('References','Appendix')):continue
                    if tt in ['References - continued','References continued']:continue
                    rows.append([tt,page_label(j)])
            story.append(table(['Section','Page'],rows,[403,50]));story.extend([Spacer(1,18),para('Page numbering: preliminary pages use Roman numerals; main text and appendices use Arabic numerals. Figures are conceptual proposed designs unless explicitly stated otherwise.','SmallF')])
            add_md_table(['Section','Page'],rows)
        elif kind=='lists':
            text='<b>Figures</b><br/>'+'<br/>'.join(f'{n} {html.escape(t)} <b>{page_label(p)}</b>' for n,t,p in figs)
            story.append(para(text,'SmallF'));story.append(Spacer(1,7))
            story.append(para('<b>Tables</b><br/>'+'<br/>'.join(f'{html.escape(t)} <b>{page_label(p)}</b>' for t,p in tabs),'SmallF'))
            story.append(para('<b>Abbreviations</b><br/>AI: Artificial Intelligence; ERS: Evasive Reverse Shell; C2: Command and Control; WSS: WebSocket over TLS; DFD: Data Flow Diagram; ERD: Entity Relationship Diagram; FYP: Final Year Project; ML: Machine Learning; PK/FK: Primary/Foreign Key.','SmallF'))
            add_md_table(['Figure','Title','Page'],[[n,t,page_label(p)] for n,t,p in figs])
            add_md_table(['Table','Page'],[[t,page_label(p)] for t,p in tabs])
            md.append('AI: Artificial Intelligence; ERS: Evasive Reverse Shell; C2: Command and Control; WSS: WebSocket over TLS; DFD: Data Flow Diagram; ERD: Entity Relationship Diagram; FYP: Final Year Project; ML: Machine Learning; PK/FK: Primary/Foreign Key.')
        elif kind=='sequence':story.extend([Sequence(),para('Figure 5.8 - Assessment interaction sequence. Proposed design.','CaptionF')]);md.append('![Figure 5.8 - Assessment interaction sequence](diagrams/figure-5-8.svg)')
        elif kind=='gantt':story.extend([Gantt(),para('Figure 10.1 - Proposed twelve-week schedule; relative weeks, not calendar commitments.','CaptionF')]);md.append('![Figure 10.1 - Proposed twelve-week schedule](diagrams/figure-10-1.svg)')

def footer(c,doc):
    i=doc.page;c.saveState()
    c.bookmarkPage('page-'+str(i));c.addOutlineEntry(pages[i-1][0],'page-'+str(i),level=0,closed=False)
    if i>1:
        c.setStrokeColor(colors.HexColor('#D7E0E5'));c.line(78,48,531,48);c.setFont('Helvetica',8);c.setFillColor(colors.HexColor(GRAY));c.drawString(78,35,'ERS OUTCOME ANALYSIS | DESIGN PROPOSAL');c.drawRightString(531,35,page_label(i));c.setFont('Helvetica',7.5);c.drawString(78,805,'FINAL YEAR PROJECT - PENETRATION TESTING AND ARTIFICIAL INTELLIGENCE')
    else:
        c.setStrokeColor(colors.HexColor(BLUE));c.setLineWidth(3);c.line(63,85,63,750)
    c.restoreState()

doc=SimpleDocTemplate(str(OUT/'FYP_Report.pdf'),pagesize=A4,leftMargin=78,rightMargin=64,topMargin=60,bottomMargin=66,title='ERS AI Outcome Analysis: Reverse Shell Session Outcome Analysis',author='ERS project team - details pending',subject='Revised FYP design proposal; no measured results')
doc.build(story,onFirstPage=footer,onLaterPages=footer)
(OUT/'FYP_Report.md').write_text('\n'.join(md),encoding='utf-8')
reader=PdfReader(OUT/'FYP_Report.pdf')
print(json.dumps({'expected_pages':len(pages),'actual_pages':len(reader.pages),'figures':len(figs),'tables':len(tabs),'bytes':(OUT/'FYP_Report.pdf').stat().st_size}))
for i,p in enumerate(reader.pages,1):print(i, (p.extract_text() or '').splitlines()[1:3])
