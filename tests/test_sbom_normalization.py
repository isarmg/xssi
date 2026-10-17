import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from sbom_normalization import normalize, selected_metadata


class SbomTests(unittest.TestCase):
    def setUp(self):
        self.root='path+file:///tmp/build/helper#xssi@1.0.0'
        self.product='path+file:///tmp/build/product#xocs@1.0.5'
        self.library='registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0'
        self.dev='registry+https://github.com/rust-lang/crates.io-index#development@1.0.0'
        self.metadata={'packages':[{'id':self.root,'name':'xssi','version':'1.0.0','source':None},{'id':self.product,'name':'xocs','version':'1.0.5','source':None},{'id':self.library,'name':'serde','version':'1.0.0','source':'registry'},{'id':self.dev,'name':'development','version':'1.0.0','source':'registry'}],
                       'resolve':{'nodes':[{'id':self.root,'deps':[{'pkg':self.product,'dep_kinds':[{'kind':None}]},{'pkg':self.dev,'dep_kinds':[{'kind':'dev'}]}]},{'id':self.product,'deps':[{'pkg':self.library,'dep_kinds':[{'kind':None}]}]},{'id':self.library,'deps':[]},{'id':self.dev,'deps':[]}]}}
        self.bom={'bomFormat':'CycloneDX','specVersion':'1.5','version':1,'metadata':{'component':{'name':'xssi','version':'1.0.0','bom-ref':self.root,'purl':'pkg:cargo/xssi@1.0.0?download_url=file://.','components':[{'bom-ref':self.root+' bin-target-0','name':'setup','version':'1.0.0','purl':'pkg:cargo/xssi@1.0.0?download_url=file://.#src/main.rs'}]}},'components':[{'bom-ref':self.product,'name':'xocs','version':'1.0.5','purl':'pkg:cargo/xocs@1.0.5?download_url=file://.'},{'bom-ref':self.library,'name':'serde','version':'1.0.0','purl':'pkg:cargo/serde@1.0.0'}],'dependencies':[{'ref':self.root,'dependsOn':[self.product]},{'ref':self.product,'dependsOn':[self.library]},{'ref':self.library,'dependsOn':[]}]}
        self.revisions={self.root:'1'*40,self.product:'2'*40}

    def run_bom(self,bom=None,metadata=None):
        return normalize(self.bom if bom is None else bom,self.metadata if metadata is None else metadata,'xssi',self.revisions,['/tmp/build'])

    def test_two_local_source_roots_and_target_fragments_are_bound(self):
        result=self.run_bom()
        self.assertEqual(result['metadata']['component']['bom-ref'],'pkg:cargo/xssi@1.0.0?source_revision='+'1'*40)
        self.assertEqual(result['components'][0]['purl'],'pkg:cargo/xocs@1.0.5?source_revision='+'2'*40)
        self.assertNotIn('components',result['metadata']['component'])
        self.assertEqual(self.bom['metadata']['component']['bom-ref'],self.root)

    def test_optional_producer_run_fields_do_not_change_delivered_bytes(self):
        original=copy.deepcopy(self.bom)
        results=[]
        for serial,timestamp in [
            ('urn:uuid:00000000-0000-4000-8000-000000000001','2026-01-01T00:00:00Z'),
            ('urn:uuid:00000000-0000-4000-8000-000000000002','2026-10-17T11:00:00Z'),
        ]:
            raw=copy.deepcopy(original)
            raw['serialNumber']=serial
            raw['metadata']['timestamp']=timestamp
            normalized=self.run_bom(raw)
            self.assertNotIn('serialNumber',normalized)
            self.assertNotIn('timestamp',normalized['metadata'])
            self.assertEqual(normalized,self.run_bom(original))
            self.assertEqual(raw['serialNumber'],serial)
            self.assertEqual(raw['metadata']['timestamp'],timestamp)
            results.append(json.dumps(normalized,sort_keys=True,ensure_ascii=False,indent=2).encode())
        self.assertEqual(results[0],results[1])

    def test_missing_transitive_dependency_or_forged_root_is_rejected(self):
        for mode in ('missing','root','duplicate','dangling','disconnected','edge'):
            bom=copy.deepcopy(self.bom)
            if mode=='missing':bom['components'].pop();bom['dependencies'].pop();bom['dependencies'][1]['dependsOn']=[]
            elif mode=='root':bom['metadata']['component']['version']='9.0.0'
            elif mode=='duplicate':bom['components'].append(copy.deepcopy(bom['components'][0]))
            elif mode=='disconnected':bom['dependencies'][0]['dependsOn']=[]
            elif mode=='edge':
                bom['dependencies'][0]['dependsOn'].append(self.library)
                bom['dependencies'][1]['dependsOn']=[]
            else:bom['dependencies'][0]['dependsOn']=['not-a-component']
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.run_bom(bom)

    def test_encoded_posix_and_windows_paths_cannot_leak(self):
        for path in ('%25252Ftmp%25252Fprivate','C%253A%255CUsers%255Csecret','file%25253A%25252F%25252F%25252Ftmp%25252Fsecret','private /root/hidden'):
            bom=copy.deepcopy(self.bom);bom['metadata']['component']['description']=path
            with self.subTest(path=path),self.assertRaises(ValueError):self.run_bom(bom)

    def test_local_revisions_and_relative_target_fragments_are_required(self):
        self.revisions.pop(self.product)
        with self.assertRaises(ValueError):self.run_bom()
        self.revisions[self.product]='2'*40
        bom=copy.deepcopy(self.bom);bom['metadata']['component']['components'][0]['purl']='pkg:cargo/xssi@1.0.0?download_url=file://.#/tmp/private'
        with self.assertRaises(ValueError):self.run_bom(bom)
        for fragment in ('..%2F..%2Fprivate','%252Fsecret%252Fprivate','%252F%252Ftmp%252Fprivate','src%255Cprivate','src%250Asecret'):
            bom=copy.deepcopy(self.bom)
            bom['metadata']['component']['components'][0]['purl']='pkg:cargo/xssi@1.0.0?download_url=file://.#'+fragment
            with self.subTest(fragment=fragment),self.assertRaises(ValueError):self.run_bom(bom)

    def test_build_only_dependency_and_its_transitive_tree_are_not_claimed_as_shipped(self):
        metadata=copy.deepcopy(self.metadata)
        bom=copy.deepcopy(self.bom)
        build='registry+https://github.com/rust-lang/crates.io-index#compiler-helper@1.0.0'
        metadata['packages'].append({'id':build,'name':'compiler-helper','version':'1.0.0','source':'registry'})
        metadata['resolve']['nodes'].append({'id':build,'deps':[{'pkg':self.dev,'dep_kinds':[{'kind':None}]}]})
        metadata['resolve']['nodes'][0]['deps'].append({'pkg':build,'dep_kinds':[{'kind':'build'}]})
        for identifier,name in [(build,'compiler-helper'),(self.dev,'development')]:
            bom['components'].append({'bom-ref':identifier,'type':'library','name':name,'version':'1.0.0'})
        bom['dependencies'][0]['dependsOn'].append(build)
        bom['dependencies'].extend([{'ref':build,'dependsOn':[self.dev]},{'ref':self.dev,'dependsOn':[]}])
        result=self.run_bom(bom,metadata)
        refs={item['bom-ref'] for item in result['components']}
        self.assertNotIn(build,refs)
        self.assertNotIn(self.dev,refs)
        self.assertTrue(all(build not in node['dependsOn'] and self.dev not in node['dependsOn'] for node in result['dependencies']))
        # If the same package is also a normal runtime dependency, it is real
        # shipped material and its runtime dependencies must remain in the BOM.
        metadata['resolve']['nodes'][0]['deps'][-1]['dep_kinds'].append({'kind':None})
        result=self.run_bom(bom,metadata)
        refs={item['bom-ref'] for item in result['components']}
        self.assertIn(build,refs)
        self.assertIn(self.dev,refs)

    def test_proc_macro_and_its_compile_time_tree_are_not_runtime_components(self):
        metadata=copy.deepcopy(self.metadata);bom=copy.deepcopy(self.bom)
        macro='registry+https://github.com/rust-lang/crates.io-index#derive-helper@1.0.0'
        metadata['packages'].append({'id':macro,'name':'derive-helper','version':'1.0.0','source':'registry','targets':[{'kind':['proc-macro']}]})
        metadata['resolve']['nodes'].append({'id':macro,'deps':[{'pkg':self.dev,'dep_kinds':[{'kind':None}]}]})
        metadata['resolve']['nodes'][0]['deps'].append({'pkg':macro,'dep_kinds':[{'kind':None}]})
        for identifier,name in [(macro,'derive-helper'),(self.dev,'development')]:
            bom['components'].append({'bom-ref':identifier,'type':'library','name':name,'version':'1.0.0'})
        bom['dependencies'][0]['dependsOn'].append(macro)
        bom['dependencies'].extend([{'ref':macro,'dependsOn':[self.dev]},{'ref':self.dev,'dependsOn':[]}])
        result=self.run_bom(bom,metadata)
        refs={item['bom-ref'] for item in result['components']}
        self.assertNotIn(macro,refs);self.assertNotIn(self.dev,refs)

    def test_independent_selected_tree_excludes_workspace_feature_union(self):
        metadata=copy.deepcopy(self.metadata);bom=copy.deepcopy(self.bom)
        android='path+file:///tmp/build/android#android-only@1.0.0'
        metadata['packages'].append({'id':android,'name':'android-only','version':'1.0.0','source':None})
        metadata['resolve']['nodes'].append({'id':android,'deps':[]})
        metadata['resolve']['nodes'][1]['deps'].append({'pkg':android,'dep_kinds':[{'kind':None}]})
        bom['components'].append({'bom-ref':android,'name':'android-only','version':'1.0.0','purl':'pkg:cargo/android-only@1.0.0?download_url=file://.'})
        bom['dependencies'][1]['dependsOn'].append(android)
        bom['dependencies'].append({'ref':android,'dependsOn':[]})
        selection={'root':self.root,'ids':[self.root,self.product,self.library],
                   'edges':{self.root:[self.product],self.product:[self.library],self.library:[]}}
        chosen=selected_metadata(metadata,selection)
        result=self.run_bom(bom,chosen)
        self.assertNotIn(android,[item['bom-ref'] for item in result['components']])
        self.assertNotIn('android-only',str(result))
        self.assertIn(android,[item['id'] for item in metadata['packages']])
        for mode in ('foreign-edge','duplicate','disconnected'):
            forged=copy.deepcopy(selection)
            if mode=='foreign-edge':forged['edges'][self.root].append(self.library)
            elif mode=='duplicate':forged['ids'].append(self.root)
            else:forged['edges'][self.root]=[]
            with self.subTest(mode=mode),self.assertRaises(ValueError):selected_metadata(metadata,forged)


if __name__=='__main__':unittest.main()
